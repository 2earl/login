/**
 * Truncates an IP address before it is stored (DESIGN §6.1): IPv4 to /24, IPv6 to /48.
 * Returns null for anything that does not parse.
 */
export function ipPrefix(ip: string | null | undefined): string | null {
  if (!ip) return null;
  const value = ip.trim();

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    const octets = value.split('.').map(Number);
    if (octets.some((o) => o > 255)) return null;
    return `${String(octets[0])}.${String(octets[1])}.${String(octets[2])}.0/24`;
  }

  if (value.includes(':')) {
    const hextets = expandIPv6(value);
    if (!hextets) return null;
    return `${hextets.slice(0, 3).join(':')}::/48`;
  }

  return null;
}

function expandIPv6(value: string): string[] | null {
  if (!/^[0-9a-fA-F:]+$/.test(value)) return null;
  const parts = value.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (parts.length === 1 && missing !== 0) return null;
  if (parts.length === 2 && missing < 1) return null;
  const all = [...head, ...Array<string>(Math.max(missing, 0)).fill('0'), ...tail];
  if (all.length !== 8 || all.some((h) => h.length === 0 || h.length > 4)) return null;
  return all.map((h) => parseInt(h, 16).toString(16));
}
