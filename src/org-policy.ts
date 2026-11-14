import type { SignInMethod } from './sessions';

/**
 * Security rules an organization sets for the accounts it manages (DESIGN §4.19): a second
 * factor, passkeys only, how long a session lasts, which ways to sign in, and from which
 * networks. Owners keep every way in and every network, so a broken identity provider or a
 * changed office network can't lock the organization out; the factor rules and session length
 * apply to them too.
 */

/** Ways to sign in an organization can turn off. SSO is never turned off here (§4.18 decides). */
export const POLICY_METHODS = ['google', 'email', 'passkey'] as const;
export type PolicyMethod = (typeof POLICY_METHODS)[number];

/** Session lengths an organization can pick, in hours. Without a rule, 7 days (§4.5). */
export const SESSION_HOURS = [1, 8, 12, 24, 72] as const;

/** At most this many network ranges. */
export const MAX_RANGES = 50;

export interface OrgPolicy {
  requireFactor: boolean;
  passkeysOnly: boolean;
  sessionHours: number | null;
  methods: PolicyMethod[];
  ipRanges: string[];
}

export const DEFAULT_POLICY: OrgPolicy = {
  requireFactor: false,
  passkeysOnly: false,
  sessionHours: null,
  methods: [...POLICY_METHODS],
  ipRanges: [],
};

/** The rules as they apply to one account: `exempt` for the organization's owners. */
export interface SessionPolicy extends OrgPolicy {
  orgId: string;
  orgName: string;
  exempt: boolean;
}

interface PolicyRow {
  require_factor: number;
  passkeys_only: number;
  session_hours: number | null;
  methods: string;
  ip_ranges: string;
}

export function policyFromRow(row: PolicyRow): OrgPolicy {
  return {
    requireFactor: row.require_factor === 1,
    passkeysOnly: row.passkeys_only === 1,
    sessionHours: row.session_hours,
    methods: row.methods
      .split(',')
      .filter((m): m is PolicyMethod => (POLICY_METHODS as readonly string[]).includes(m)),
    ipRanges: row.ip_ranges.split('\n').filter(Boolean),
  };
}

export async function readPolicy(db: D1Database, orgId: string): Promise<OrgPolicy> {
  const row = await db
    .prepare(
      'SELECT require_factor, passkeys_only, session_hours, methods, ip_ranges FROM org_policies WHERE org_id = ?',
    )
    .bind(orgId)
    .first<PolicyRow>();
  return row ? policyFromRow(row) : { ...DEFAULT_POLICY, methods: [...DEFAULT_POLICY.methods] };
}

export async function savePolicy(
  db: D1Database,
  now: number,
  orgId: string,
  policy: OrgPolicy,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO org_policies (org_id, require_factor, passkeys_only, session_hours, methods, ip_ranges, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
       ON CONFLICT (org_id) DO UPDATE SET require_factor = ?2, passkeys_only = ?3, session_hours = ?4,
         methods = ?5, ip_ranges = ?6, updated_at = ?7`,
    )
    .bind(
      orgId,
      policy.requireFactor || policy.passkeysOnly ? 1 : 0,
      policy.passkeysOnly ? 1 : 0,
      policy.sessionHours,
      policy.methods.join(','),
      policy.ipRanges.join('\n'),
      now,
    )
    .run();
}

/** The rules for this account, if an active organization manages it and set any. */
export async function policyFor(db: D1Database, userId: string): Promise<SessionPolicy | null> {
  const row = await db
    .prepare(
      `SELECT p.require_factor, p.passkeys_only, p.session_hours, p.methods, p.ip_ranges,
              o.id AS org_id, o.name AS org_name,
              EXISTS (SELECT 1 FROM org_members m
                      WHERE m.org_id = o.id AND m.user_id = u.id AND m.role = 'owner') AS exempt
       FROM users u JOIN organizations o ON o.id = u.managed_by AND o.status = 'active'
       JOIN org_policies p ON p.org_id = o.id
       WHERE u.id = ?`,
    )
    .bind(userId)
    .first<PolicyRow & { org_id: string; org_name: string; exempt: number }>();
  return row
    ? { ...policyFromRow(row), orgId: row.org_id, orgName: row.org_name, exempt: row.exempt === 1 }
    : null;
}

/** Whether a session started this way may continue (or a sign-in this way may happen). */
export function methodAllowed(policy: SessionPolicy, method: SignInMethod | null): boolean {
  if (policy.exempt || method === 'saml') return true;
  return method !== null && (policy.methods as string[]).includes(method);
}

/** Whether a request from this address may use the account. */
export function networkAllowed(policy: SessionPolicy, ip: string | null): boolean {
  if (policy.exempt || policy.ipRanges.length === 0) return true;
  return ip !== null && policy.ipRanges.some((range) => inRange(ip, range));
}

// ---- Network ranges ---------------------------------------------------------------------------

/** An address as a bigint and its family, or null. */
function parseIp(text: string): { value: bigint; bits: 32 | 128 } | null {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(text)) {
    const parts = text.split('.').map(Number);
    if (parts.some((p) => p > 255)) return null;
    return { value: parts.reduce((acc, p) => (acc << 8n) | BigInt(p), 0n), bits: 32 };
  }
  if (!/^[0-9a-f:]+$/i.test(text) || !text.includes(':')) return null;
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  if (groups.some((g) => g.length === 0 || g.length > 4)) return null;
  return {
    value: groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n),
    bits: 128,
  };
}

/** A range in CIDR notation (or a single address), normalised; null if it isn't one. */
export function parseRange(text: string): string | null {
  const [address = '', prefixText] = text.trim().toLowerCase().split('/');
  const ip = parseIp(address);
  if (!ip) return null;
  const prefix = prefixText === undefined ? ip.bits : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > ip.bits) return null;
  if (prefixText !== undefined && !/^\d{1,3}$/.test(prefixText)) return null;
  // Narrower than /8 (IPv4) or /16 (IPv6) would let in much of the internet: almost surely a mistake.
  if (prefix < (ip.bits === 32 ? 8 : 16)) return null;
  return `${address}/${String(prefix)}`;
}

/** Whether the address is in the range. */
export function inRange(ipText: string, range: string): boolean {
  const ip = parseIp(ipText.trim().toLowerCase());
  const [address = '', prefixText = ''] = range.split('/');
  const net = parseIp(address);
  if (!ip || !net || ip.bits !== net.bits) return false;
  const shift = BigInt(net.bits - Number(prefixText));
  return ip.value >> shift === net.value >> shift;
}

/** Parses the ranges an owner typed, one per line or separated by commas. */
export function parseRanges(text: string): { ranges: string[]; invalid: string[] } {
  const items = text
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
  const ranges: string[] = [];
  const invalid: string[] = [];
  for (const item of items) {
    const range = parseRange(item);
    if (range) {
      if (!ranges.includes(range)) ranges.push(range);
    } else invalid.push(item);
  }
  return { ranges, invalid };
}
