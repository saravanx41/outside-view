// Local runner: serves public/ and the two /api routes. `node server.mjs` then open http://localhost:8787
import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import web from "./api/web.js";
import whois from "./api/whois.js";

const root = path.join(path.dirname(new URL(import.meta.url).pathname), "public");
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml" };
const vercel = JSON.parse(await fs.readFile(new URL("./vercel.json", import.meta.url)));
const headers = vercel.headers[0].headers;

http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  headers.forEach((h) => res.setHeader(h.key, h.value));
  if (u.pathname === "/api/web") return web(req, res);
  if (u.pathname === "/api/whois") return whois(req, res);
  const f = path.join(root, path.normalize(u.pathname === "/" ? "/index.html" : u.pathname));
  if (!f.startsWith(root)) { res.statusCode = 403; return res.end(); }
  try {
    const body = await fs.readFile(f);
    res.setHeader("content-type", types[path.extname(f)] || "application/octet-stream");
    res.end(body);
  } catch { res.statusCode = 404; res.end("not found"); }
}).listen(process.env.PORT || 8787, () => console.log("http://localhost:" + (process.env.PORT || 8787)));
