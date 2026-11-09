import { describe, expect, it } from 'vitest';
import { pkceChallenge, timingSafeEqual } from '../src/crypto';
import { ipPrefix } from '../src/net';
import { escapeHtml } from '../src/pages';
import { safeReturnTo } from '../src/return-to';

describe('safeReturnTo', () => {
  it.each([
    [undefined, '/account'],
    ['/account', '/account'],
    ['/account/apps?x=1', '/account/apps?x=1'],
    ['https://evil.example/', '/account'],
    ['//evil.example/', '/account'],
    ['/\\evil.example', '/account'],
    ['/admin/users', '/admin/users'],
    // Normalised before the prefix check: the result is the path the browser would request.
    ['/account/../admin', '/admin'],
    ['/administrator', '/account'],
    ['/oauth/token', '/account'],
    ['javascript:alert(1)', '/account'],
    ['/account\n', '/account'],
  ])('%s → %s', (input, expected) => {
    expect(safeReturnTo(input)).toBe(expected);
  });
});

describe('ipPrefix', () => {
  it.each([
    ['203.0.113.77', '203.0.113.0/24'],
    ['2001:db8:abcd:12::1', '2001:db8:abcd::/48'],
    ['2001:db8::1', '2001:db8:0::/48'],
    ['::1', '0:0:0::/48'],
    ['999.1.1.1', null],
    ['not-an-ip', null],
    [null, null],
  ])('%s → %s', (input, expected) => {
    expect(ipPrefix(input)).toBe(expected);
  });
});

describe('pkceChallenge', () => {
  it('matches the RFC 7636 appendix B example', async () => {
    expect(await pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
  });
});

describe('timingSafeEqual', () => {
  it('compares strings', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true);
    expect(timingSafeEqual('abc', 'abd')).toBe(false);
    expect(timingSafeEqual('abc', 'abcd')).toBe(false);
  });
});

describe('escapeHtml', () => {
  it('escapes markup characters', () => {
    expect(escapeHtml(`<a href="x">'&'</a>`)).toBe(
      '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;',
    );
  });
});
