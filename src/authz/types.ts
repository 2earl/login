/**
 * The authorization model's vocabulary (DESIGN §4.32). Each service that keeps data people share
 * declares its permissions and system roles here, in code: a permission means nothing without the
 * code that enforces it, so both ship in the same change.
 *
 * Names:
 * - a permission is `<service>:<object>.<action>`, e.g. `emanet:cases.write`;
 * - a system role is `<service>:<name>`, e.g. `emanet:partner_admin`, with no dot;
 * - a custom role (an organization's own, phase 13b) is `rol_…`.
 */

/** An organization member's base role (DESIGN §4.14). */
export type BaseOrgRole = 'owner' | 'admin' | 'auditor' | 'member';
/** A 2earl staff member's base role (DESIGN §4.29). */
export type BaseStaffRole = 'owner' | 'admin' | 'support';

export interface SystemRole {
  /** How the role reads on pages, in English; the Turkish is in the catalog. */
  name: string;
  /** Permissions of the same service. */
  permissions: readonly string[];
  /** Where it can be held: in one organization, or across 2earl (staff). */
  assignable: 'org' | 'platform';
  /** Only owners may give it, and giving it alerts the owners (DESIGN §4.27). */
  privileged?: boolean;
}

export interface ServiceAuthz {
  /** Permission → what it lets someone do, in English; the Turkish is in the catalog. */
  permissions: Readonly<Record<string, string>>;
  /** System roles, keyed by their full ID (`<service>:<name>`). */
  roles: Readonly<Record<string, SystemRole>>;
  /** The system role each organization base role implies in this service. Unlisted: none. */
  orgDefaults?: Readonly<Partial<Record<BaseOrgRole, string>>>;
  /** The system role each staff base role implies, at platform scope. Unlisted: none. */
  staffDefaults?: Readonly<Partial<Record<BaseStaffRole, string>>>;
  /** Pairs of roles one principal may not hold together in one scope (separation of duties). */
  exclusive?: readonly (readonly [string, string])[];
  /**
   * OAuth scope → the permissions a token with it can use. A scope that isn't listed carries
   * none; `'*'` carries every permission. Effective access is always scopes ∩ permissions.
   */
  scopeGrants: Readonly<Record<string, readonly string[] | '*'>>;
}

export const PERMISSION_PATTERN = /^[a-z][a-z0-9-]*:[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
export const SYSTEM_ROLE_PATTERN = /^[a-z][a-z0-9-]*:[a-z][a-z0-9_]*$/;
export const CUSTOM_ROLE_PATTERN = /^rol_[A-Za-z0-9_-]{8,40}$/;

/** The service a permission or system role belongs to: the part before the first colon. */
export function serviceOf(name: string): string {
  const colon = name.indexOf(':');
  return colon > 0 ? name.slice(0, colon) : '';
}
