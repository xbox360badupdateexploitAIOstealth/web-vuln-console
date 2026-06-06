// backend/utils/cidrExpand.js
// CIDR / IP range expander utility.
// Supports: single IP, CIDR notation (IPv4 /8 through /32),
// dash-range (192.168.1.1-192.168.1.50), and plain hostnames/domains.
// Returns a flat array of host strings, capped at MAX_HOSTS to prevent runaway.

const MAX_HOSTS = 1024; // hard safety cap

/**
 * @param {string} input — one of:
 *   - "192.168.1.0/24"  → expands to .1–.254 (usable, skips .0 and .255)
 *   - "10.0.0.1-10.0.0.20"  → dash range
 *   - "192.168.1.5"      → single IP
 *   - "example.com"      → returned as-is in a 1-element array
 * @returns {string[]} array of host strings
 */
export function expandCidr(input) {
  const trimmed = (input || '').trim();
  if (!trimmed) return [];

  // CIDR notation
  const cidrMatch = trimmed.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
  if (cidrMatch) {
    return expandCidrBlock(cidrMatch[1], parseInt(cidrMatch[2], 10));
  }

  // Dash range (same /24 block only enforced by MAX_HOSTS cap)
  const dashMatch = trimmed.match(
    /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/
  );
  if (dashMatch) {
    return expandDashRange(dashMatch[1], dashMatch[2]);
  }

  // Single IP (valid dotted-quad)
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
    return [trimmed];
  }

  // Hostname / domain — return as-is
  return [trimmed];
}

/**
 * Expand a list of newline/comma-separated target strings.
 * Each line may itself be a CIDR, range, IP, or hostname.
 * @param {string} multilineInput
 * @returns {string[]}
 */
export function expandTargetList(multilineInput) {
  const lines = (multilineInput || '')
    .split(/[\n,]+/)
    .map((l) => l.trim())
    .filter(Boolean);

  const out = [];
  for (const line of lines) {
    const expanded = expandCidr(line);
    for (const host of expanded) {
      if (out.length >= MAX_HOSTS) break;
      out.push(host);
    }
    if (out.length >= MAX_HOSTS) break;
  }
  return out;
}

// ─── internals ──────────────────────────────────────────────────────────────

function ipToInt(ip) {
  return ip
    .split('.')
    .reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function intToIp(n) {
  return [
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8)  & 0xff,
     n         & 0xff,
  ].join('.');
}

function expandCidrBlock(baseIp, prefixLen) {
  if (prefixLen < 8 || prefixLen > 32) {
    throw new RangeError(`CIDR prefix /${prefixLen} out of supported range /8–/32`);
  }

  const base   = ipToInt(baseIp);
  const mask   = prefixLen === 32 ? 0xffffffff : ~(0xffffffff >>> prefixLen) >>> 0;
  const net    = (base & mask) >>> 0;
  const bcast  = (net | (~mask >>> 0)) >>> 0;

  if (prefixLen === 32) return [intToIp(net)];
  if (prefixLen === 31) return [intToIp(net), intToIp(bcast)]; // RFC 3021 point-to-point

  // Usable range: network+1 → broadcast-1
  const first = net + 1;
  const last  = bcast - 1;
  const count = last - first + 1;

  const hosts = [];
  const limit = Math.min(count, MAX_HOSTS);
  for (let i = 0; i < limit; i++) {
    hosts.push(intToIp(first + i));
  }
  return hosts;
}

function expandDashRange(startIp, endIp) {
  const start = ipToInt(startIp);
  const end   = ipToInt(endIp);
  if (end < start) throw new RangeError(`Dash range end < start: ${startIp}-${endIp}`);

  const hosts = [];
  const limit = Math.min(end - start + 1, MAX_HOSTS);
  for (let i = 0; i < limit; i++) {
    hosts.push(intToIp(start + i));
  }
  return hosts;
}
