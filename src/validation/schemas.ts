/** Shared Zod schemas for validating tool inputs. Uses node:net for real IP checks. */
import { isIP } from "node:net";
import { z } from "zod";

function stripPort(v: string): string {
  // IPv4:port -> IPv4 ; leave bracketed/opaque IPv6 alone.
  if (isIP(v) !== 0) return v;
  const idx = v.lastIndexOf(":");
  if (idx > 0 && v.indexOf(":") === idx) return v.slice(0, idx); // single colon => v4:port
  return v;
}

function isCidr(v: string): boolean {
  const parts = v.split("/");
  if (parts.length !== 2) return false;
  const [ip, prefix] = parts;
  const fam = isIP(ip ?? "");
  if (fam === 0) return false;
  const p = Number(prefix);
  if (!Number.isInteger(p)) return false;
  return fam === 4 ? p >= 0 && p <= 32 : p >= 0 && p <= 128;
}

/** A Tailscale IP (v4 or v6), optionally with :port (for whois). */
export const ipSchema = z
  .string()
  .min(2)
  .max(64)
  .refine((v) => isIP(v) !== 0 || isIP(stripPort(v)) !== 0, { message: "Must be a valid IP address (optionally ip:port)." });

/** Exit node: an IP, a MagicDNS/hostname, or "" to clear. */
export const exitNodeSchema = z
  .string()
  .max(256)
  .refine((v) => v === "" || !v.startsWith("-"), { message: "Invalid exit node value." });

/** A hostname label. */
export const hostnameSchema = z
  .string()
  .min(1)
  .max(63)
  .regex(/^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/, { message: "Invalid hostname label." });

/** A single CIDR (v4 or v6). */
export const cidrSchema = z.string().refine(isCidr, { message: "Must be a CIDR, e.g. 10.0.0.0/24 or fd00::/64." });

/** An array of CIDRs; [] is allowed (withdraw all). */
export const cidrArraySchema = z.array(cidrSchema).max(256);

/** An ACL tag: tag:name (lowercase letters, digits, hyphen). */
export const tagSchema = z.string().regex(/^tag:[a-z0-9-]+$/, { message: "Tags must look like tag:name (lowercase)." });

/** A REST device id (opaque string). */
export const deviceIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9]+$/, { message: "Device id must be alphanumeric." });
