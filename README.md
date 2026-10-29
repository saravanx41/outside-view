# Outside View: passive attack surface console

Web version of `recon.py` for Task A. Enter a domain, press **Run passive scan**, and the page
collects and writes up the same sections as the Task A report: domains and attribution, vendors,
email posture, edge protections, top 5 risks with HK$ costs, limits, and the host appendix.
This public copy holds no scan results; every report is collected live when you press Run.

## How it works

* `public/engine.js` runs in the visitor's browser: crt.sh (Cert Spotter fallback), Google and
  Cloudflare DNS over HTTPS, Team Cymru ASN, AWS ip-ranges, IANA RDAP. All of these allow CORS.
* `api/web.js` does what a browser cannot: one GET, no redirects, to the apex, `www`, `app`, `api`
  and `security.txt` of the requested domain only. Private addresses are refused. 6 requests a minute per IP.
* `api/whois.js` queries HKIRC WHOIS for `.hk` names and returns only company, registrar and dates.
* `bowtie.com.hk` loads the agreed Task A scope (same lists as `recon.py`).

Rules of engagement as built: no port scans, no brute force, no logins, no requests to dev,
staging, admin or internal hosts, no personal data kept (email SANs and WHOIS contacts dropped).

## Run locally

    node server.mjs        # Node 18+, no dependencies; open http://localhost:8787

## Deploy

    vercel deploy --prod   # static public/ plus the two /api functions; headers from vercel.json

The GitHub Pages copy is static: header checks are skipped and .hk registrant data for the Task A preset comes from the published HKIRC record. Point `<meta name="asm-api">` at a deployed server to enable both.

