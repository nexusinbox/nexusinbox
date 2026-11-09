#!/usr/bin/env node
// Certificate Transparency watch for the cloud-AI domain (docs/33 §14).
//
// Every certificate a public CA issues is logged. This asks Cert Spotter
// for recent issuances under agent-inbox.ai and flags any that do not
// match what we expect: Cloudflare's edge certificate for the zone, the
// Vercel redirect, the relay's own certificate, and one Let's Encrypt
// certificate per computer at <id>.mcp.agent-inbox.ai. A name a computer
// never asked for, another CA, a second certificate for the same computer
// within a month, or a burst of new ones may mean someone is issuing
// certificates for our names.
//
// Usage: node scripts/ct_watch.mjs [--days N] [--json]
//   Exits 0 and prints the findings; `--json` prints them as JSON (the
//   workflow turns each into an issue). Needs only public data.

const DOMAIN = "agent-inbox.ai";
const MCP_HOST = /^[a-km-np-z2-9]{10}\.mcp\.agent-inbox\.ai$/;
const LE = "Let's Encrypt";
// Cloudflare's Universal SSL for the zone (apex and one-level wildcard).
const CLOUDFLARE_CAS = new Set(["Sectigo", LE, "Google Trust Services", "SSL.com"]);
const REISSUE_WINDOW_DAYS = 30;
const BURST_PER_DAY = 20;

const DAY_MS = 24 * 60 * 60 * 1000;

/** The CA's short name as Cert Spotter gives it. */
export function issuerName(issuance) {
  return issuance.issuer?.friendly_name || issuance.issuer?.name || "unknown";
}

/** Why a single issuance is unexpected, or null when it is expected. */
export function unexpected(issuance) {
  const names = issuance.dns_names ?? [];
  const ca = issuerName(issuance);
  if (names.length === 0) return "no names";
  if (names.every((n) => n === DOMAIN || n === `*.${DOMAIN}`)) {
    return CLOUDFLARE_CAS.has(ca) ? null : `zone certificate from ${ca}`;
  }
  if (names.length === 1 && (names[0] === `relay.${DOMAIN}` || names[0] === `app.${DOMAIN}`)) {
    return ca === LE ? null : `${names[0]} from ${ca}`;
  }
  if (names.length === 1 && MCP_HOST.test(names[0])) {
    return ca === LE ? null : `computer certificate from ${ca}`;
  }
  return `unexpected names: ${names.join(", ")}`;
}

/**
 * Findings for issuances that started within `days` of `now`. `all` is
 * every issuance known (older ones show reissues).
 */
export function findings(all, now, days) {
  const since = now - days * DAY_MS;
  const recent = all.filter((c) => Date.parse(c.not_before) >= since);
  const out = [];
  for (const c of recent) {
    const reason = unexpected(c);
    if (reason) out.push({ cert: c, reason });
  }
  // A computer gets one certificate and renews it about every 60 days. A
  // second one for the same name within a month was not asked for by it.
  for (const c of recent) {
    const [name] = c.dns_names ?? [];
    if (c.dns_names?.length !== 1 || !MCP_HOST.test(name)) continue;
    const start = Date.parse(c.not_before);
    const earlier = all.find(
      (o) =>
        o !== c &&
        o.dns_names?.length === 1 &&
        o.dns_names[0] === name &&
        Date.parse(o.not_before) < start &&
        start - Date.parse(o.not_before) < REISSUE_WINDOW_DAYS * DAY_MS,
    );
    if (earlier) out.push({ cert: c, reason: `second certificate for ${name} within ${REISSUE_WINDOW_DAYS} days` });
  }
  // Many new computer certificates in one day.
  const perDay = new Map();
  for (const c of recent) {
    if (c.dns_names?.length === 1 && MCP_HOST.test(c.dns_names[0])) {
      const day = c.not_before.slice(0, 10);
      perDay.set(day, (perDay.get(day) ?? 0) + 1);
    }
  }
  for (const [day, n] of perDay) {
    if (n > BURST_PER_DAY) {
      out.push({ cert: null, day, reason: `${n} computer certificates on ${day} (more than ${BURST_PER_DAY})` });
    }
  }
  return out;
}

async function fetchAll() {
  const all = [];
  let after = "";
  for (let page = 0; page < 50; page++) {
    const url = new URL("https://api.certspotter.com/v1/issuances");
    url.searchParams.set("domain", DOMAIN);
    url.searchParams.set("include_subdomains", "true");
    url.searchParams.append("expand", "dns_names");
    url.searchParams.append("expand", "issuer");
    if (after) url.searchParams.set("after", after);
    const res = await fetch(url, { headers: { "User-Agent": "nexusinbox-ct-watch" } });
    if (!res.ok) throw new Error(`Cert Spotter: HTTP ${res.status}`);
    const batch = await res.json();
    if (!Array.isArray(batch) || batch.length === 0) break;
    all.push(...batch);
    after = batch[batch.length - 1].id;
  }
  return all;
}

async function main() {
  const args = process.argv.slice(2);
  const daysArg = args.indexOf("--days");
  const days = daysArg >= 0 ? Number(args[daysArg + 1]) : 3;
  const all = await fetchAll();
  const found = findings(all, Date.now(), days);
  if (args.includes("--json")) {
    console.log(
      JSON.stringify(
        found.map((f) => ({
          key: f.cert ? f.cert.cert_sha256.slice(0, 16) : `burst-${f.day}`,
          reason: f.reason,
          names: f.cert?.dns_names ?? [],
          issuer: f.cert ? issuerName(f.cert) : null,
          not_before: f.cert?.not_before ?? null,
          cert_sha256: f.cert?.cert_sha256 ?? null,
        })),
      ),
    );
    return;
  }
  console.log(`${all.length} certificates known for ${DOMAIN}; ${found.length} findings in the last ${days} days`);
  for (const f of found) console.log(`- ${f.reason}${f.cert ? ` (${f.cert.not_before}, ${f.cert.cert_sha256.slice(0, 16)})` : ""}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
