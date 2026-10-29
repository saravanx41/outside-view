// HKIRC WHOIS for .hk names. Returns registrant company, registrar and dates only;
// every contact field is discarded before the response is built (PDPO).
import net from "node:net";
import { isDomain, limited, send } from "./_guard.js";

function query(d) {
  return new Promise((resolve, reject) => {
    let buf = "";
    const s = net.connect(43, "whois.hkirc.hk", () => s.write(d + "\r\n"));
    s.setTimeout(15000, () => { s.destroy(); reject(new Error("timeout")); });
    s.on("data", (c) => { buf += c; if (buf.length > 200000) s.destroy(); });
    s.on("end", () => resolve(buf)); s.on("close", () => resolve(buf)); s.on("error", reject);
  });
}

export default async function handler(req, res) {
  if (limited(req, 30, "whois")) return send(res, 429, { error: "Too many requests, wait a minute" });
  const d = String(new URL(req.url, "http://x").searchParams.get("d") || "").toLowerCase();
  if (!isDomain(d) || !d.endsWith(".hk")) return send(res, 400, { error: ".hk domains only" });
  let w = "";
  for (let i = 0; i < 2 && !/Company English Name/i.test(w); i++) {
    try { w = await query(d); } catch { w = ""; }
    if (!/Company English Name/i.test(w) && i === 0) await new Promise((r) => setTimeout(r, 4000));
  }
  const grab = (k) => ((w.match(new RegExp(k + "[^:\\n]*:\\s*(.+)")) || [])[1] || "").trim();
  send(res, 200, { registrant_company: grab("Company English Name"), registrar: grab("Registrar Name"),
    created: grab("Commencement Date"), expires: grab("Expiry Date") });
}
