# Testing with real identity providers

Unit and end-to-end tests run login's single sign-on and directory sync against fakes. A company
will connect Microsoft Entra ID, Okta or Google, and those differ from the fakes in ways only a real
tenant shows. This is the checklist to run once per provider before the first company is onboarded,
and again after any change to `src/saml*.ts`, `src/sso-oidc.ts` or `src/scim*.ts`.

Everything happens in production (`login.2earl.com`) in a **test organization**, at a **test
domain**, so no real person's account is touched.

## 0. Preparation (once)

1. **A test domain.** A subdomain of a domain you control works for Entra ID and Okta, for example
   `sso-test.2earl.com`. Google may want a domain of its own; a cheap separate domain avoids the
   question. Mail to it isn't needed: the identity providers and login only check DNS.
2. **A test organization.** Sign in to login with your own account, create an organization
   ("SSO test"), add the test domain on **Domains & SSO** and publish the TXT record it shows at
   `_2earl-challenge.<domain>`. Wait until it says *Verified*.
3. **Decide about managing.** Run each provider once **without** "Manage accounts at <domain>",
   then once **with** it (section 5). Without, SSO signs people in and SCIM only records
   directory users; with, SSO and SCIM create managed accounts (DESIGN §4.18).
4. **Two browsers.** Your owner session in one; the test person's sign-ins in another browser or a
   private window, so the owner session isn't replaced.

What to keep for each run: the provider, the date, which checks passed, and the organization's
activity for the run (Activity → Download → JSON, last 7 days). Activity names people by ID and,
for members, by address; it contains no secrets.

## 1. What login shows you

On **Domains & SSO** (owner, after a recent proof it's you):

| For | login gives | You enter |
|---|---|---|
| OpenID Connect | Redirect URI `https://login.2earl.com/sso/<org>/oidc` | Issuer URL, client ID, client secret |
| SAML | Entity ID `https://login.2earl.com/saml/<org>`, Reply (ACS) URL `…/acs` (HTTP-POST), metadata `…/metadata` | The provider's entity ID, sign-in URL (HTTP-Redirect), signing certificate |
| Directory (SCIM) | Base URL `https://login.2earl.com/scim/v2`, a token (`scim_…`, shown once) | — |

Only one way of single sign-on is on at a time; turning OpenID Connect on turns SAML off and the
other way round. Test each in turn.

## 2. The directory check script

Before connecting a provider's provisioning, check the SCIM endpoint with the same requests Entra ID
and Okta send:

```sh
SCIM_TOKEN=scim_… SCIM_DOMAIN=sso-test.2earl.com node scripts/scim-check.mjs
```

It discovers the configuration, creates a user at the domain, patches it the Entra way
(`"active": "False"`) and the Okta way (a value object), replaces it, creates a group, adds and
removes the member, renames the group, then deletes both. Every line says `pass` or `FAIL`; it
exits non-zero on any failure. Run it **without** managing turned on: at a managed domain the user
it creates becomes a managed account, and its deletion is only scheduled (30 days).

Microsoft also offers a [SCIM Validator](https://scimvalidator.microsoft.com/) that runs its own
requests against the endpoint: base URL as above, the token, "Discover schema", "Enable group
tests". Expected failures: soft delete (login deletes; DESIGN §4.18 explains the 30 days) and
filters other than `userName eq`, `externalId eq`, `displayName eq`.

## 3. Per provider

### Microsoft Entra ID

Tenant: any Entra tenant where you're an administrator; a new one comes with an Azure account.
Automatic provisioning may need Entra ID P1; a P1 trial covers the test. Add the test domain as a
custom domain (Entra → Domain names) and create a test user at it.

**OpenID Connect.** App registrations → New registration, single tenant, redirect URI (Web) as
login shows it. Certificates & secrets → new client secret. In login, the issuer is
`https://login.microsoftonline.com/<tenant ID>/v2.0` (not `common` or `organizations`: refused).
Optional: Token configuration → add the optional claim `email`; without it login uses
`preferred_username`, which is the sign-in name.

**SAML.** Enterprise applications → New → Create your own (non-gallery) → Single sign-on → SAML.
Identifier = login's entity ID, Reply URL = the ACS URL. Unique user identifier (Name ID) =
`user.userprincipalname` or `user.mail`, whichever is the address at the test domain. From
"SAML certificates" download the Base64 certificate; in login, the provider's entity ID is the
"Microsoft Entra Identifier" and the sign-in URL is the "Login URL". Assign the test user.

**Provisioning.** The same enterprise application → Provisioning → Automatic. Tenant URL = the
SCIM base URL, secret token = a login SCIM token. Test connection, then map only `userName`,
`active`, `externalId`, `name.givenName`, `name.familyName`, `displayName`; assign the test user and
a test group; "Provision on demand" for the user, then start provisioning. Entra ID runs about
every 40 minutes, so "Provision on demand" is the quick check.

### Okta

Tenant: an Okta Integrator Free Plan organization. Create a test user at the test domain (Okta
doesn't check the domain).

**OpenID Connect.** Applications → Create App Integration → OIDC → Web application. Sign-in
redirect URI as login shows it; grant type Authorization Code. The issuer is the organization's
URL (`https://<your org>.okta.com`), from its default authorization server, not
`…/oauth2/default`, unless you change it in both places. Assign the test user.

**SAML.** Create App Integration → SAML 2.0. Single sign-on URL = the ACS URL ("Use this for
Recipient URL and Destination URL" on), Audience URI = login's entity ID, Name ID format
EmailAddress, application username Email. From "View SAML setup instructions": the issuer, the sign-in
URL and the certificate for login.

**Provisioning.** SCIM needs an app with provisioning: Create App Integration → SAML 2.0 (as
above), then General → Provisioning: SCIM. SCIM connector base URL = the SCIM base URL, unique
identifier `userName`, actions: push new users, push profile updates, push groups; authentication
HTTP Header, the login token. Turn on "Create users", "Update user attributes", "Deactivate users".
Push Groups → the test group.

### Google

Tenant: Google Cloud Identity Free (or Workspace) on the test domain; Google asks for a TXT record
for its own verification. Create a test user. Google has no SCIM provisioning to custom apps:
test OpenID Connect, and SAML if the edition allows it.

**OpenID Connect.** In a Google Cloud project of that organization: Google Auth platform →
Audience: **Internal** (only the organization's accounts) → Clients → Web application, redirect URI
as login shows it. In login, the issuer is `https://accounts.google.com`. login also checks
`hd`, the account's Workspace domain, so a personal Google account made with a work address is
refused.

**SAML.** Admin console → Apps → Web and mobile apps → Add custom SAML app. ACS URL and entity ID
from login; Name ID format EMAIL, Name ID Basic Information → Primary email. Download the IdP
metadata's certificate, SSO URL and entity ID for login. Turn the app on for the test user.

## 4. Checks for each provider

Run these with the test user in the second browser. Each check names where to see the result.

**Single sign-on (OpenID Connect, then SAML)**
1. `/login` → "Sign in with your organization (SSO)" → the test address → the provider → back,
   signed in. Account page shows the address. *Activity: a sign-in by SSO.*
2. The same again: the same account, no second account.
3. An address at another domain (a second user at a domain that isn't verified, where the
   provider allows it): refused with a message, no session.
4. Okta and Entra ID: unassign the test user from the app, try again: the provider refuses; login
   isn't reached.
5. Google: a personal Google account (not in the organization) choosing the Google screen: refused
   by the app being Internal; if it gets through, login refuses it (`hd`).
6. Wrong certificate (SAML): paste another certificate in login, try: refused, nothing created.
   Put the right one back.
7. Switching: turn SAML on while OpenID Connect is on: OpenID Connect turns off, and the other way
   round.

**Directory (Entra ID and Okta)**
1. Provision the test user: it appears under Domains & SSO → Directory.
2. Change the user's name in the provider: the name changes in login.
3. Deactivate (Okta) or block sign-in / unassign (Entra ID): `active` false arrives.
4. Create a group, add the user, push it: the group and its member appear.
5. Mark the group "admin" in login: the provisioned member becomes an admin of the organization;
   remove them from the group in the provider: they're a member again.
6. Delete the user in the provider (Entra ID: after the soft-delete period, or "Provision on
   demand" after deletion): it's gone from Directory.

## 5. Again with managed accounts

Turn on "Manage accounts at <test domain>" and repeat:
- First SSO sign-in of a new test user creates a **managed** account (Members shows it as managed).
- SCIM provisioning creates the account before anyone signs in.
- "Require single sign-on": the test user signing in with an email code is refused; you (owner)
  are not.
- Rules: require a second factor → the test user is sent to add one at the next request.
- Deactivate in the provider → the test user's session ends at its next request, apps lose access.
- SCIM `DELETE` → deactivated now, deletion scheduled in 30 days; reactivate from Members to
  cancel.
- App access: "Only allow the apps below" with nothing allowed → the test user can't connect an
  app (try promptshare.cc); allow it → they can.

Turn managing off at the end: the accounts become their own again (DESIGN §4.18 Releasing), then
delete them from Members or leave them deactivated.

## 6. When something fails

- **Activity** (owners and admins) says what login refused and why, in words.
- `/admin/orgs` (2earl owner) shows the organization's setup.
- The provider's own logs: Entra ID → Sign-in logs and Provisioning logs; Okta → System Log;
  Google → Admin console → Reporting → SAML / OAuth logs.
- For a fix, keep the run's JSON activity download and the provider's error text; never paste a
  client secret, SCIM token or SAML response with a real person's data into an issue.

## 7. After the run

Record the date and result in the table below in the same pull request as any fixes.

| Provider | OpenID Connect | SAML | Directory | Managed | Date |
|---|---|---|---|---|---|
| Microsoft Entra ID | not yet | not yet | not yet | not yet | |
| Okta | not yet | not yet | not yet | not yet | |
| Google | not yet | not yet | — | not yet | |
