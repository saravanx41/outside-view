// One GET per allowlisted production page, no redirects followed (Task A rules of engagement).
// Only the apex, www, app and api of the requested domain, plus security.txt, are ever fetched.
import { isDomain, publicHost, limited, send } from "./_guard.js";

const ALLOWED = ["", "www", "app", "api"];
const SEC = ["strict-transport-security", "content-security-policy", "content-security-policy-report-only",
  "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"];
const DISCLOSE = ["server", "x-powered-by", "api-release", "api-commit-hash", "x-aspnet-version", "x-generator"];
const UA = "passive-asm-console/1.0 (one GET per page, no redirects)";

async function page(url, wantBody) {
  const host = new URL(url).hostname;
  try {
    await publicHost(host);
    const r = await fetch(url, { redirect: "manual", headers: { "user-agent": UA }, signal: AbortSignal.timeout(10000) });
    const h = Object.fromEntries([...r.headers].map(([k, v]) => [k.toLowerCase(), v]));
    let body = "";
    if (wantBody && r.status === 200) body = (await r.text()).slice(0, 1_000_000); else r.body?.cancel();
    const csp = h["content-security-policy"] || "";
    const out = {
      url, status: r.status, location: h.location || "",
      security_headers: Object.fromEntries(SEC.filter((k) => k in h).map((k) => [k, h[k]])),
      disclosure_headers: Object.fromEntries(DISCLOSE.filter((k) => k in h).map((k) => [k, /hash/.test(k) ? "<present, value withheld>" : h[k]])),
      edge: /cloudfront/i.test(h.via || "") ? "CloudFront" : h["cf-ray"] ? "Cloudflare" : (h.server || ""),
      csp_mode: csp ? "enforced" : h["content-security-policy-report-only"] ? "report-only" : "none",
      csp_script_src_permissive: /script-src[^;]*'unsafe-inline'[^;]*https:/.test(csp),
    };
    if (body && /\/\/www\./.test(url) && !url.endsWith(".txt")) {
      const tags = [...body.matchAll(/<script[^>]+src="(https?:\/\/[^"]+)"[^>]*>/g)];
      out.external_scripts = tags.map((m) => m[1].split("?")[0]);
      out.external_scripts_without_sri = tags.filter((m) => !/integrity=/.test(m[0]) && new URL(m[1]).hostname !== host).map((m) => m[1].split("?")[0]);
      out.third_party_hosts = [...new Set([...body.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/g)].map((m) => m[1]))].filter((x) => x !== host).sort();
    } else if (wantBody && r.status === 202) out.note = "202: WAF challenge, page body not served to a non browser client";
    if (url.endsWith("security.txt") && body) out.securitytxt_fields = [...new Set([...body.matchAll(/^([A-Za-z-]+):/gm)].map((m) => m[1]))].sort();
    return out;
  } catch (e) {
    return { url, error: String(e.message || e) };
  }
}

export default async function handler(req, res) {
  if (limited(req, 6, "web")) return send(res, 429, { error: "Too many requests, wait a minute" });
  const q = new URL(req.url, "http://x").searchParams;
  const d = String(q.get("domain") || "").toLowerCase();
  if (!isDomain(d)) return send(res, 400, { error: "invalid domain" });
  const labels = String(q.get("hosts") ?? "www,").split(",").filter((l) => ALLOWED.includes(l));
  const urls = [...new Set(labels)].map((l) => `https://${l ? l + "." : ""}${d}/`);
  const sec = `https://${labels.includes("www") ? "www." : ""}${d}/.well-known/security.txt`;
  const web = await Promise.all([...urls.map((u) => page(u, /\/\/www\./.test(u))), page(sec, true)]);
  let hsts = {};
  try {
    const j = await (await fetch(`https://hstspreload.org/api/v2/status?domain=${d}`, { signal: AbortSignal.timeout(8000) })).json();
    hsts = { [d]: j.status || "unknown" };
  } catch { hsts = { [d]: "unknown" }; }
  send(res, 200, { web, hsts });
}
