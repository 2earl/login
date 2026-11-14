/**
 * Security audit trail (DESIGN §6.1). Never pass tokens, codes, cookies, full URLs or email
 * addresses in `detail`. Writing an audit event never fails the request.
 */
export type AuditEvent =
  | 'login.started'
  | 'login.succeeded'
  | 'login.denied'
  | 'login.failed'
  | 'login.code_sent'
  | 'login.code_failed'
  | 'login.code_refused'
  | 'identity.added'
  | 'identity.removed'
  | 'allowlist.pinned'
  | 'user.created'
  | 'logout'
  | 'device.approved'
  | 'session.ended'
  | 'consent.approved'
  | 'consent.denied'
  | 'consent.reused'
  | 'grant.revoked'
  | 'grant.refused'
  | 'account.exported'
  | 'account.deletion_started'
  | 'account.deletion_stopped'
  | 'user.deleted'
  | 'user.deletion_delivered'
  | 'mfa.enrolled'
  | 'mfa.removed'
  | 'mfa.verified'
  | 'mfa.failed'
  | 'mfa.locked'
  | 'mfa.recovery_codes_created'
  | 'mfa.recovery_code_used'
  | 'admin.invitation_added'
  | 'admin.invitation_removed'
  | 'admin.user_suspended'
  | 'admin.user_reactivated'
  | 'admin.user_deleted'
  | 'admin.mfa_reset'
  | 'admin.client_trusted'
  | 'admin.client_untrusted'
  | 'admin.client_registered'
  | 'admin.client_deleted'
  | 'admin.resource_server_created'
  | 'admin.resource_server_deleted'
  | 'admin.signup_changed'
  | 'admin.org_suspended'
  | 'admin.org_reactivated'
  | 'admin.org_deleted'
  | 'org.created'
  | 'org.renamed'
  | 'org.deleted'
  | 'org.deletion_delivered'
  | 'org.invited'
  | 'org.invitation_revoked'
  | 'org.invitation_declined'
  | 'org.joined'
  | 'org.role_changed'
  | 'org.member_removed'
  | 'org.left'
  | 'org.ownership_passed'
  | 'org.domain_added'
  | 'org.domain_verified'
  | 'org.domain_removed'
  | 'org.scim_token_created'
  | 'org.scim_token_revoked'
  | 'org.saml_saved'
  | 'org.oidc_saved'
  | 'org.domain_managed'
  | 'org.domain_unmanaged'
  | 'org.require_sso_changed'
  | 'org.policy_changed'
  | 'org.account_managed'
  | 'org.account_kept_personal'
  | 'org.accounts_released'
  | 'org.account_deactivated'
  | 'org.account_reactivated'
  | 'org.account_deleted'
  | 'scim.account_created'
  | 'scim.group_created'
  | 'scim.group_updated'
  | 'scim.group_deleted'
  | 'scim.role_changed'
  | 'org.group_role_changed'
  | 'org.apps_restricted'
  | 'org.app_allowed'
  | 'org.app_disallowed'
  | 'org.audit_exported'
  | 'org.audit_stream_changed'
  | 'org.api_key_created'
  | 'org.api_key_revoked'
  | 'scim.account_deactivated'
  | 'scim.account_reactivated'
  | 'scim.account_deletion_scheduled'
  | 'org.account_deletion_due'
  | 'scim.user_created'
  | 'scim.user_updated'
  | 'scim.user_deleted'
  | 'scim.member_added'
  | 'scim.member_removed';

export async function audit(
  db: D1Database,
  now: number,
  event: AuditEvent,
  fields: {
    actorUserId?: string | null;
    clientId?: string | null;
    ipPrefix?: string | null;
    detail?: Record<string, string | number | boolean | null>;
  } = {},
): Promise<void> {
  try {
    await db
      .prepare(
        `INSERT INTO audit_events (id, at, event, actor_user_id, client_id, ip_prefix, detail)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        crypto.randomUUID(),
        now,
        event,
        fields.actorUserId ?? null,
        fields.clientId ?? null,
        fields.ipPrefix ?? null,
        fields.detail ? JSON.stringify(fields.detail) : null,
      )
      .run();
  } catch (error) {
    console.error('audit write failed', event, error instanceof Error ? error.name : 'unknown');
  }
}
