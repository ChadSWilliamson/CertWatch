/**
 * net-guard.mjs
 * -----------------------------------------------------------------
 * Safety check before Vigía Recon connects to anything a customer
 * typed in. Customers control the hostname, so without this they
 * could point the scanner at private addresses (127.0.0.1, cloud
 * metadata at 169.254.169.254, a 10.x network) and use Vigía Recon
 * to poke at things it should never touch. This is standard SSRF
 * protection for any tool that fetches user-supplied URLs.
 */

import dns from "node:dns/promises";
import net from "node:net";

export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
      (a === 169 && b === 254) ||            // link-local / cloud metadata
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    if (v.startsWith("::ffff:")) return isPrivateIp(v.slice(7));
    return (
      v === "::" || v === "::1" ||
      v.startsWith("fc") || v.startsWith("fd") || // unique local
      v.startsWith("fe8") || v.startsWith("fe9") || v.startsWith("fea") || v.startsWith("feb") || // link-local
      v.startsWith("ff") // multicast
    );
  }
  return true; // not an IP at all — treat as unsafe
}

// Labels are separated by literal dots and total length is capped at 253,
// so this can't backtrack catastrophically.
// eslint-disable-next-line security/detect-unsafe-regex
const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function isValidPublicHostname(hostname) {
  return HOSTNAME_RE.test(String(hostname).toLowerCase());
}

/**
 * Resolves the hostname and returns its public IPv4 addresses.
 * Throws if the name is malformed or ANY address is private.
 */
export async function resolvePublicIps(hostname) {
  if (!isValidPublicHostname(hostname)) {
    throw new Error(`"${hostname}" is not a valid public hostname`);
  }
  const v4 = await dns.resolve4(hostname).catch(() => []);
  const v6 = await dns.resolve6(hostname).catch(() => []);
  const all = [...v4, ...v6];
  if (all.length === 0) throw new Error(`${hostname} has no A/AAAA records`);
  const bad = all.filter(isPrivateIp);
  if (bad.length) throw new Error(`${hostname} resolves to a private address (${bad.join(", ")}) — refusing to scan`);
  return v4;
}
