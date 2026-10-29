// Shared guards for the two server routes: domain validation, SSRF block, rate limit.
import dns from "node:dns/promises";

export const isDomain = (d) => /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d);

function isPrivate(ip) {
  if (ip.includes(":")) return /^(::1?$|fc|fd|fe80|::ffff:(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.))/i.test(ip);
  return /^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|22[4-9]\.|2[3-5]\d\.)/.test(ip);
}

// Refuse hosts that resolve to private or reserved space, so the route cannot reach internal networks.
export async function publicHost(host) {
  const addrs = await dns.lookup(host, { all: true });
  if (!addrs.length || addrs.some((a) => isPrivate(a.address))) throw new Error("host resolves to private address space");
}

const hits = new Map();
export function limited(req, max = 20, route = "") {
  const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "").split(",")[0].trim();
  const key = route + "|" + ip, now = Date.now(), win = hits.get(key)?.filter((t) => now - t < 60000) || [];
  win.push(now); hits.set(key, win);
  return win.length > max;
}

export function send(res, code, body) {
  res.statusCode = code;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  res.end(JSON.stringify(body));
}
