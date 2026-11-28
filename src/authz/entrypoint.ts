import { WorkerEntrypoint } from 'cloudflare:workers';
import { AUTHZ_SERVICES } from '../services';
import {
  check,
  effective,
  subjectsWith,
  type Context,
  type Resource,
  type Subject,
} from './engine';
import { serviceOf } from './types';

/**
 * The authorization API for 2earl's apps (DESIGN §4.34): what a person may do, read live. A named
 * entrypoint for Service Bindings only; the public Internet can't reach it. Each app binds it
 * with its own service ID as props, and may only ask about that service's permissions:
 *
 * ```jsonc
 * { "binding": "AUTHZ", "service": "login", "entrypoint": "Authorization",
 *   "props": { "service": "emanet" } }
 * ```
 *
 * Shaped like the OpenID AuthZEN Authorization API 1.0 (subject, action, resource, context).
 * Wrong questions throw (an unknown permission, another service's permission, malformed input),
 * so a misconfigured app fails loudly instead of quietly denying everyone. See AUTHORIZATION.md.
 */

export interface AuthorizationProps {
  service: string;
}

export interface CheckQuery {
  subject: Subject;
  action: string;
  /** The organization the question is about; omit for 2earl-wide (staff) permissions. */
  orgId?: string | null;
  resource?: Resource;
  context?: CallerContext;
}

/** What an app may tell login about the request: the token's scopes. */
export interface CallerContext {
  scopes?: readonly string[];
}

const MAX_EVALUATIONS = 50;
const ID = /^[A-Za-z0-9_.:@-]{1,100}$/;
const ORG_ID = /^org_[A-Za-z0-9_-]{1,60}$/;
const SCOPE = /^[\x21-\x7e]{1,200}$/;

class BadQuery extends Error {
  override name = 'AuthorizationQueryError';
}

function subjectOf(raw: unknown): Subject {
  const s = raw as Partial<Subject> | null;
  if (
    !s ||
    (s.type !== 'user' && s.type !== 'service_account') ||
    typeof s.id !== 'string' ||
    !ID.test(s.id)
  ) {
    throw new BadQuery('subject must be { type: "user" | "service_account", id }');
  }
  return { type: s.type, id: s.id };
}

function orgOf(raw: unknown): string | null {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== 'string' || !ORG_ID.test(raw)) throw new BadQuery('orgId must be an org_… ID');
  return raw;
}

function resourceOf(raw: unknown): Resource | undefined {
  if (raw === undefined || raw === null) return undefined;
  const r = raw as Partial<Resource>;
  if (typeof r.type !== 'string' || typeof r.id !== 'string') {
    throw new BadQuery('resource must be { type, id }');
  }
  return { type: r.type, id: r.id };
}

/** Only the token's scopes cross over; nothing else a caller sends reaches the engine. */
function contextOf(raw: unknown): Context | undefined {
  if (raw === undefined || raw === null) return undefined;
  const scopes = (raw as CallerContext).scopes;
  if (scopes === undefined) return {};
  if (!Array.isArray(scopes) || scopes.length > 50 || !scopes.every((s) => SCOPE.test(String(s)))) {
    throw new BadQuery('context.scopes must be a list of up to 50 scopes');
  }
  return { scopes: scopes.map(String) };
}

export class Authorization extends WorkerEntrypoint<Env, AuthorizationProps> {
  /** The calling app's service, from its binding's props. */
  private caller(): string {
    const service = (this.ctx.props as Partial<AuthorizationProps> | undefined)?.service;
    if (typeof service !== 'string' || !AUTHZ_SERVICES.some((s) => s.id === service)) {
      throw new BadQuery('bind Authorization with props: { service: "<your service ID>" }');
    }
    return service;
  }

  private ownAction(action: unknown): string {
    if (typeof action !== 'string') throw new BadQuery('action must be a permission');
    if (serviceOf(action) !== this.caller()) {
      throw new BadQuery(`${this.caller()} may only ask about its own permissions`);
    }
    return action;
  }

  /** One decision. */
  async check(query: CheckQuery): Promise<{ decision: boolean }> {
    const context = contextOf(query.context);
    const resource = resourceOf(query.resource);
    const decision = await check(this.env, {
      subject: subjectOf(query.subject),
      action: this.ownAction(query.action),
      orgId: orgOf(query.orgId),
      ...(resource ? { resource } : {}),
      ...(context ? { context } : {}),
    });
    return { decision };
  }

  /** Several decisions for one subject, in order; at most 50. */
  async checkMany(query: {
    subject: Subject;
    orgId?: string | null;
    evaluations: { action: string; resource?: Resource }[];
    context?: CallerContext;
  }): Promise<{ decision: boolean }[]> {
    if (!Array.isArray(query.evaluations) || query.evaluations.length > MAX_EVALUATIONS) {
      throw new BadQuery(`evaluations must be a list of up to ${String(MAX_EVALUATIONS)}`);
    }
    const subject = subjectOf(query.subject);
    const orgId = orgOf(query.orgId);
    const context = contextOf(query.context);
    const actions = query.evaluations.map((e) => ({
      action: this.ownAction(e.action),
      resource: resourceOf(e.resource),
    }));
    return Promise.all(
      actions.map(async ({ action, resource }) => ({
        decision: await check(this.env, {
          subject,
          action,
          orgId,
          ...(resource ? { resource } : {}),
          ...(context ? { context } : {}),
        }),
      })),
    );
  }

  /**
   * Everything the subject may do in the calling service, in one organization or (without
   * `orgId`) across 2earl: what a page needs to decide what to show. `scoped` lists permissions
   * held only for some resources.
   */
  async permissionsOf(query: {
    subject: Subject;
    orgId?: string | null;
    context?: CallerContext;
  }): Promise<{
    permissions: string[];
    scoped: Record<string, string[]>;
    roles: string[];
    baseRole: string | null;
  }> {
    const context = contextOf(query.context);
    const found = await effective(this.env, {
      subject: subjectOf(query.subject),
      service: this.caller(),
      orgId: orgOf(query.orgId),
      ...(context ? { context } : {}),
    });
    return {
      permissions: [...found.permissions].sort(),
      scoped: Object.fromEntries(
        [...found.scoped].map(([permission, resources]) => [permission, [...resources].sort()]),
      ),
      roles: found.roles,
      baseRole: found.baseRole,
    };
  }

  /** Who in an organization holds a permission for all of its resources; up to 1,000. */
  async subjectsWith(query: { action: string; orgId: string }): Promise<Subject[]> {
    const orgId = orgOf(query.orgId);
    if (orgId === null) throw new BadQuery('orgId is required');
    return subjectsWith(this.env, { action: this.ownAction(query.action), orgId });
  }
}
