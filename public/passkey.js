// Passkeys on /account/security (add) and /mfa (sign in). The server makes and checks every
// challenge; this script only carries them between the server and the browser's WebAuthn API.
// Loaded only on those two pages (script-src 'self', connect-src 'self').

const supported =
  typeof window.PublicKeyCredential === 'function' &&
  typeof navigator.credentials?.create === 'function';

function fromB64url(text) {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function toB64url(buffer) {
  let binary = '';
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function post(url, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    credentials: 'same-origin',
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || 'Something went wrong. Try again.');
  return data;
}

function explain(error) {
  if (error?.name === 'NotAllowedError') return 'The passkey request was cancelled or timed out.';
  if (error?.name === 'InvalidStateError') return 'This passkey is already on your account.';
  if (error?.name === 'SecurityError') return 'This browser refused the passkey request.';
  return error?.message || 'Something went wrong. Try again.';
}

function wire(button, run) {
  const status = document.getElementById(button.dataset.status);
  if (!supported) {
    button.disabled = true;
    if (status) status.textContent = 'This browser can’t use passkeys.';
    return;
  }
  button.hidden = false;
  button.addEventListener('click', async () => {
    button.disabled = true;
    if (status) status.textContent = '';
    try {
      const next = await run(button);
      if (next) window.location.assign(next);
    } catch (error) {
      if (status) status.textContent = explain(error);
    } finally {
      button.disabled = false;
    }
  });
}

async function register(button) {
  const options = await post('/account/security/passkeys/options', {});
  if (options.redirect) return options.redirect; // a fresh second-factor check comes first
  const credential = await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: fromB64url(options.challenge),
      user: { ...options.user, id: fromB64url(options.user.id) },
      excludeCredentials: (options.excludeCredentials ?? []).map((c) => ({
        ...c,
        id: fromB64url(c.id),
      })),
    },
  });
  const nameField = document.getElementById(button.dataset.label);
  const result = await post('/account/security/passkeys', {
    label: nameField ? nameField.value : '',
    next: button.dataset.next ?? '',
    response: {
      id: credential.id,
      rawId: toB64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        clientDataJSON: toB64url(credential.response.clientDataJSON),
        attestationObject: toB64url(credential.response.attestationObject),
        transports: credential.response.getTransports?.() ?? [],
      },
    },
  });
  return result.redirect;
}

async function authenticate(button) {
  const options = await post('/mfa/passkey/options', {});
  const credential = await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: fromB64url(options.challenge),
      allowCredentials: (options.allowCredentials ?? []).map((c) => ({
        ...c,
        id: fromB64url(c.id),
      })),
    },
  });
  const result = await post('/mfa/passkey', {
    returnTo: button.dataset.returnTo ?? '',
    response: {
      id: credential.id,
      rawId: toB64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        clientDataJSON: toB64url(credential.response.clientDataJSON),
        authenticatorData: toB64url(credential.response.authenticatorData),
        signature: toB64url(credential.response.signature),
        userHandle: credential.response.userHandle
          ? toB64url(credential.response.userHandle)
          : undefined,
      },
    },
  });
  return result.redirect;
}

for (const button of document.querySelectorAll('[data-passkey="register"]')) wire(button, register);
for (const button of document.querySelectorAll('[data-passkey="authenticate"]')) {
  wire(button, authenticate);
}
