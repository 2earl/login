import type { ServiceAuthz } from './types';

/**
 * login's own permissions (DESIGN §4.32): what organization members (§4.14, §4.28) and 2earl staff
 * (§4.29) may do in login itself. The roles reproduce the tables in those sections exactly;
 * `test/authz-parity.test.ts` checks every combination against them.
 */
export const LOGIN_AUTHZ: ServiceAuthz = {
  permissions: {
    // In an organization.
    'login:members.read': 'See the organization’s members',
    'login:activity.read': 'See and download the organization’s activity',
    'login:members.invite': 'Invite people and withdraw invitations',
    'login:members.manage': 'Change roles of members, auditors and admins, and remove them',
    'login:owners.manage': 'Make, unmake and remove owners',
    'login:organization.manage': 'Rename and delete the organization',
    // Across 2earl (staff).
    'login:staff.view': 'Open the admin area: people, organizations, the security log',
    'login:users.sign_out': 'Sign a person out everywhere',
    'login:orgs.resend_invitations': 'Send an organization setup invitation again',
    'login:users.manage': 'Suspend, reactivate, reset a second factor and delete people',
    'login:signup.manage': 'Open and close sign-up, and invite people to sign up',
    'login:orgs.create': 'Create organizations and invite people to set them up',
    'login:orgs.manage': 'Suspend, reactivate and delete organizations',
    'login:apps.manage': 'Manage registered apps and resource servers',
    'login:staff.manage': 'Give, change and take staff roles, and act on other staff',
  },
  roles: {
    'login:owner': {
      name: 'Owner',
      assignable: 'org',
      privileged: true,
      permissions: [
        'login:members.read',
        'login:activity.read',
        'login:members.invite',
        'login:members.manage',
        'login:owners.manage',
        'login:organization.manage',
      ],
    },
    'login:admin': {
      name: 'Admin',
      assignable: 'org',
      permissions: [
        'login:members.read',
        'login:activity.read',
        'login:members.invite',
        'login:members.manage',
      ],
    },
    'login:auditor': {
      name: 'Auditor',
      assignable: 'org',
      permissions: ['login:members.read', 'login:activity.read'],
    },
    'login:member': {
      name: 'Member',
      assignable: 'org',
      permissions: ['login:members.read'],
    },
    'login:staff_support': {
      name: 'Support',
      assignable: 'platform',
      permissions: ['login:staff.view', 'login:users.sign_out', 'login:orgs.resend_invitations'],
    },
    'login:staff_admin': {
      name: 'Admin',
      assignable: 'platform',
      permissions: [
        'login:staff.view',
        'login:users.sign_out',
        'login:orgs.resend_invitations',
        'login:users.manage',
        'login:signup.manage',
        'login:orgs.create',
        'login:orgs.manage',
        'login:apps.manage',
      ],
    },
    'login:staff_owner': {
      name: 'Owner',
      assignable: 'platform',
      privileged: true,
      permissions: [
        'login:staff.view',
        'login:users.sign_out',
        'login:orgs.resend_invitations',
        'login:users.manage',
        'login:signup.manage',
        'login:orgs.create',
        'login:orgs.manage',
        'login:apps.manage',
        'login:staff.manage',
      ],
    },
  },
  orgDefaults: {
    owner: 'login:owner',
    admin: 'login:admin',
    auditor: 'login:auditor',
    member: 'login:member',
  },
  staffDefaults: {
    owner: 'login:staff_owner',
    admin: 'login:staff_admin',
    support: 'login:staff_support',
  },
  // login's own pages aren't reached with OAuth tokens; no scope carries these permissions.
  scopeGrants: {},
};

/**
 * Permissions that are never given by an assignment, only by a base role: whoever holds them can
 * make owners or staff, so they follow the rules of §4.14 and §4.29 alone.
 */
export const NEVER_ASSIGNABLE: ReadonlySet<string> = new Set([
  'login:owners.manage',
  'login:organization.manage',
  'login:staff.manage',
]);
