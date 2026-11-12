# Turning on Microsoft, GitHub and Apple sign-in

login.2earl.com can offer "Continue with Microsoft", "Continue with GitHub" and "Continue with
Apple" next to Google (DESIGN §4.14). Each stays **off** until two things are set:

| Provider | Public client ID: `wrangler.jsonc` `vars` (by PR) | Secret: GitHub `production` environment secret |
|---|---|---|
| Microsoft | `MICROSOFT_CLIENT_ID` | `MICROSOFT_CLIENT_SECRET` |
| GitHub | `GITHUB_CLIENT_ID` | `GH_OAUTH_CLIENT_SECRET` (GitHub reserves the `GITHUB_` prefix; the Worker sees it as `GITHUB_CLIENT_SECRET`) |
| Apple | `APPLE_CLIENT_ID`, `APPLE_TEAM_ID`, `APPLE_KEY_ID` | `APPLE_PRIVATE_KEY` |

Client IDs aren't secret: send them in a PR (or ask Claude to). Secrets go only into GitHub's
`production` environment. `deploy.yml` uploads them on the next deploy. To turn a provider off
again, empty its client ID by PR.

Every provider gets the same redirect address pattern: `https://login.2earl.com/callback/<provider>`.

## Microsoft

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com) → **App registrations** →
   **New registration**.
   - Name: `2earl`
   - Supported account types: **Accounts in any organizational directory and personal Microsoft
     accounts**
   - Redirect URI: platform **Web**, `https://login.2earl.com/callback/microsoft`
2. **Token configuration → Add optional claim → ID**: tick `email` and `xms_edov`. Accept the
   prompt to add the Microsoft Graph `email` permission.
   - Without `xms_edov`, only personal accounts (outlook.com, hotmail.com, live.com) can sign
     in. Work and school accounts are refused, because their `email` claim is whatever the
     organization's admin typed, unless the domain is verified.
3. **Certificates & secrets → New client secret.** Copy the **Value** (not the ID) into the
   GitHub secret `MICROSOFT_CLIENT_SECRET`.
   - Secrets expire after at most 24 months. Put the date in your calendar and replace it
     before then.
4. **Overview → Application (client) ID** goes into `MICROSOFT_CLIENT_ID`.

Optional: **Branding & properties** (publisher domain `2earl.com`, links to the privacy policy
and terms) removes the "unverified" label on Microsoft's consent screen.

## GitHub

1. Go to [github.com/organizations/2earl/settings/applications](https://github.com/organizations/2earl/settings/applications)
   → **OAuth Apps** → **New OAuth App**. Use an OAuth App, not a GitHub App.
   - Application name: `2earl`
   - Homepage URL: `https://2earl.com`
   - Authorization callback URL: `https://login.2earl.com/callback/github`
   - Leave "Enable Device Flow" off.
2. **Generate a new client secret** and copy it into the GitHub secret `GH_OAUTH_CLIENT_SECRET`.
3. The **Client ID** goes into `GITHUB_CLIENT_ID`.

login asks for `read:user user:email` and accepts only the account's **primary, verified**
address. GitHub's token is used for two reads and then dropped; it is never stored.

## Apple

Needs a paid [Apple Developer Program](https://developer.apple.com/programs/) membership.

1. **Certificates, Identifiers & Profiles → Identifiers → +**:
   - an **App ID** (for example `com.2earl.app`) with **Sign in with Apple** ticked;
   - a **Services ID** (for example `com.2earl.login`) with **Sign in with Apple** ticked.
     **Configure** it with that App ID as primary, domain `login.2earl.com`, and return URL
     `https://login.2earl.com/callback/apple`.
2. **Keys → +**: a key with **Sign in with Apple**, for the App ID above. Download the `.p8`
   file. Apple lets you download it **once**.
   - The whole file content (`-----BEGIN PRIVATE KEY----- …`) goes into the GitHub secret
     `APPLE_PRIVATE_KEY`.
   - The **Key ID** goes into `APPLE_KEY_ID`.
3. Your **Team ID** (top right in the developer portal) goes into `APPLE_TEAM_ID`. The Services
   ID goes into `APPLE_CLIENT_ID`.
4. **Email to Apple's private relay addresses.** People can hide their address behind
   `…@privaterelay.appleid.com`. Apple forwards mail to those addresses only from registered
   senders. Under **Services → Sign in with Apple for Email Communication → Configure**, add
   `2earl.com` and `noreply@2earl.com`. Otherwise sign-in codes and security emails to these
   addresses bounce.

## After turning one on

- Try it from a private window: sign up with the new provider, sign out, sign in again.
- Then, signed in with your own account, use **Add …** under "How you sign in" to link it.
- Each provider is an independent controller of its own account data: the privacy policy names
  them (2earl.com/privacy, §3).
