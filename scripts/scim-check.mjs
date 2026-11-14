#!/usr/bin/env node
// Runs the SCIM requests Microsoft Entra ID and Okta send against a live login, for one test
// organization, and says what passed (docs/ENTERPRISE_TESTING.md §2).
//
//   SCIM_TOKEN=scim_… SCIM_DOMAIN=sso-test.example.com node scripts/scim-check.mjs
//
// SCIM_URL defaults to https://login.2earl.com/scim/v2. Everything it creates is removed at the
// end. At a domain the organization manages, provisioning creates accounts and DELETE schedules
// their deletion (DESIGN §4.18): use a test domain.

const base = (process.env.SCIM_URL ?? 'https://login.2earl.com/scim/v2').replace(/\/+$/, '');
const token = process.env.SCIM_TOKEN;
const domain = process.env.SCIM_DOMAIN;
if (!token || !domain) {
  console.error('Set SCIM_TOKEN and SCIM_DOMAIN (a verified test domain of the organization).');
  process.exit(2);
}

const USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
const GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const run = Date.now().toString(36);
let failures = 0;

async function call(method, path, body) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/scim+json',
      ...(body ? { 'Content-Type': 'application/scim+json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await response.text();
  let json;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: response.status, json };
}

function check(name, ok, detail = '') {
  if (!ok) failures += 1;
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${!ok && detail ? `  (${detail})` : ''}`);
}

const userName = `scim-check-${run}@${domain}`;
let userId = null;
let groupId = null;

try {
  // Discovery: what both clients read first.
  const config = await call('GET', '/ServiceProviderConfig');
  check('ServiceProviderConfig', config.status === 200, `HTTP ${config.status}`);
  const types = await call('GET', '/ResourceTypes');
  check(
    'ResourceTypes lists User and Group',
    types.status === 200 &&
      ['User', 'Group'].every((id) => types.json?.Resources?.some((r) => r.id === id)),
  );

  // Okta and Entra ID look the user up before creating it.
  const before = await call(
    'GET',
    `/Users?filter=${encodeURIComponent(`userName eq "${userName}"`)}`,
  );
  check('filter by userName (none yet)', before.status === 200 && before.json?.totalResults === 0);

  const created = await call('POST', '/Users', {
    schemas: [USER],
    userName,
    externalId: `ext-${run}`,
    name: { givenName: 'Scim', familyName: 'Check' },
    emails: [{ primary: true, value: userName, type: 'work' }],
    active: true,
  });
  userId = created.json?.id ?? null;
  check('create user', created.status === 201 && Boolean(userId), `HTTP ${created.status}`);
  const duplicate = await call('POST', '/Users', { schemas: [USER], userName, active: true });
  check('duplicate user is 409', duplicate.status === 409, `HTTP ${duplicate.status}`);

  // Entra ID: capitalized ops, path per attribute.
  const entraPatch = await call('PATCH', `/Users/${userId}`, {
    schemas: [PATCH],
    Operations: [
      { op: 'Replace', path: 'name.givenName', value: 'Scimmy' },
      { op: 'Replace', path: 'active', value: 'False' },
    ],
  });
  check(
    'Entra-style PATCH (active "False")',
    entraPatch.status === 200 && entraPatch.json?.active === false,
    `HTTP ${entraPatch.status}`,
  );
  // Okta: no path, a value object.
  const oktaPatch = await call('PATCH', `/Users/${userId}`, {
    schemas: [PATCH],
    Operations: [{ op: 'replace', value: { active: true } }],
  });
  check(
    'Okta-style PATCH (value object)',
    oktaPatch.status === 200 && oktaPatch.json?.active === true,
    `HTTP ${oktaPatch.status}`,
  );
  const put = await call('PUT', `/Users/${userId}`, {
    schemas: [USER],
    userName,
    name: { givenName: 'Scim', familyName: 'Check' },
    active: true,
  });
  check('PUT user', put.status === 200, `HTTP ${put.status}`);

  // Groups.
  const group = await call('POST', '/Groups', {
    schemas: [GROUP],
    displayName: `scim-check-${run}`,
    members: [],
  });
  groupId = group.json?.id ?? null;
  check('create group', group.status === 201 && Boolean(groupId), `HTTP ${group.status}`);
  const add = await call('PATCH', `/Groups/${groupId}`, {
    schemas: [PATCH],
    Operations: [{ op: 'Add', path: 'members', value: [{ value: userId }] }],
  });
  check('add member (Entra)', add.status === 200 || add.status === 204, `HTTP ${add.status}`);
  const lean = await call(
    'GET',
    `/Groups?filter=${encodeURIComponent(`displayName eq "scim-check-${run}"`)}&excludedAttributes=members`,
  );
  check(
    'filter group, members excluded',
    lean.status === 200 &&
      lean.json?.totalResults === 1 &&
      !('members' in (lean.json?.Resources?.[0] ?? {})),
  );
  const full = await call('GET', `/Groups/${groupId}`);
  check('member listed', full.json?.members?.some((m) => m.value === userId) === true);
  const remove = await call('PATCH', `/Groups/${groupId}`, {
    schemas: [PATCH],
    Operations: [{ op: 'remove', path: `members[value eq "${userId}"]` }],
  });
  check(
    'remove member (Okta)',
    remove.status === 200 || remove.status === 204,
    `HTTP ${remove.status}`,
  );
  const rename = await call('PATCH', `/Groups/${groupId}`, {
    schemas: [PATCH],
    Operations: [{ op: 'Replace', value: { displayName: `scim-check-${run}-renamed` } }],
  });
  check(
    'rename group (Entra, no path)',
    rename.json?.displayName === `scim-check-${run}-renamed`,
    `HTTP ${rename.status}`,
  );
} catch (error) {
  failures += 1;
  console.log(`FAIL  ${error instanceof Error ? error.message : String(error)}`);
} finally {
  if (groupId) {
    const gone = await call('DELETE', `/Groups/${groupId}`);
    check('delete group', gone.status === 204, `HTTP ${gone.status}`);
  }
  if (userId) {
    const gone = await call('DELETE', `/Users/${userId}`);
    check('delete user', gone.status === 204, `HTTP ${gone.status}`);
    const after = await call('GET', `/Users/${userId}`);
    check('deleted user is 404', after.status === 404, `HTTP ${after.status}`);
  }
}

console.log(failures === 0 ? '\nAll checks passed.' : `\n${String(failures)} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
