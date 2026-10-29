/* Passive attack surface engine. Runs in the browser and in Node 18+.
   Collection mirrors recon.py: CT logs, DNS over HTTPS, Team Cymru ASN, AWS ip-ranges,
   RDAP. HTTP to the target goes only through /api/web, which allowlists production pages. */
(function (G) {
  "use strict";

  // ---------------- presets (scope a reviewer already agreed for Task A) ----------------
  const PRESETS = {
    "bowtie.com.hk": {
      brand: ["bowtie.com.hk", "bowtie.hk", "virtualinsurer.hk", "virtualinsurer.com.hk"],
      ctRoots: ["bowtie.com.hk", "bowtie.hk", "virtualinsurer.hk"],
      extra: ["marketing.bowtie.com.hk"],
      related: ["bowtiego.com", "gobowtie.com", "bowtiejphealth.com"],
      founded: "2017-11",
      lookalikes: ["bowtielife.com", "bowtiemedical.com", "bowite.com", "powtie.com",
        "bowtieinsurance.com", "bowtiecare.com", "bowtiepay.com", "bowtiegroup.net", "bowtiehk.com"],
      httpHosts: ["www", "", "app", "api"],
      // HKIRC has no RDAP and port 43 is unreachable from a browser; public registry data (29 Oct)
      // used only when no server route is available. Contact fields were never collected.
      whois: {
        "bowtie.com.hk": { registrant_company: "BOWTIE LIFE INSURANCE COMPANY LIMITED", registrar: "CSC Corporate Domains, Inc.", created: "21-11-2017", expires: "23-11-2026" },
        "bowtie.hk": { registrant_company: "BOWTIE LIFE INSURANCE COMPANY LIMITED", registrar: "CSC Corporate Domains, Inc.", created: "30-08-2018", expires: "30-08-2027" },
        "virtualinsurer.hk": { registrant_company: "BOWTIE LIFE INSURANCE COMPANY LIMITED", registrar: "CSC Corporate Domains, Inc.", created: "13-12-2018", expires: "13-12-2026" },
        "virtualinsurer.com.hk": { registrant_company: "BOWTIE LIFE INSURANCE COMPANY LIMITED", registrar: "CSC Corporate Domains, Inc.", created: "13-12-2018", expires: "04-01-2027" },
      },
      sector: "insurer",
    },
  };

  const DKIM_SELECTORS = { google: "Google Workspace", selector1: "Microsoft 365",
    selector2: "Microsoft 365", k1: "Mailchimp", s1: "SendGrid", zendesk1: "Zendesk",
    zendesk2: "Zendesk", hs1: "HubSpot" };
  const TWO_LEVEL = ["com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk", "idv.hk", "co.uk", "org.uk",
    "com.sg", "com.au", "net.au", "co.jp", "co.nz", "com.cn", "com.tw", "co.in", "com.my", "co.kr"];
  const NONPROD = /(^|[.-])(dev|staging|stg|uat|qa|test|sandbox|preview|demo|pr)([.-]|$)/;
  const INTERNAL = /(^|[.-])(admin|internal|intranet|vpn|openvpn|vdi|jenkins|grafana|kibana|argocd|gitlab|bastion|hotdesk|room|orgchart|reimburse|llm-gateway|mcp-gateway|gws-mcp-gateway|data-mcp-gateway|ai|sso|jira|wiki|vault|citrix|rdp)([.-]|$)/;
  const DAY = 4000; // HK$ per engineer day

  // ---------------- small utilities ----------------
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const uniq = (a) => [...new Set(a)];
  const isDomain = (d) => /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d);
  function registrable(n) {
    const p = n.split(".");
    const two = p.slice(-2).join(".");
    return TWO_LEVEL.includes(two) ? p.slice(-3).join(".") : two;
  }
  function envOf(name) {
    if (NONPROD.test(name)) return "non-prod";
    if (INTERNAL.test(name)) return "internal";
    return "prod";
  }
  async function pool(items, n, fn) {
    const out = new Array(items.length); let i = 0;
    await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
      while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); }
    }));
    return out;
  }
  async function getJSON(url, timeout = 20000, headers = {}) {
    const c = new AbortController(); const t = setTimeout(() => c.abort(), timeout);
    try {
      const r = await fetch(url, { signal: c.signal, headers });
      if (!r.ok) throw new Error("HTTP " + r.status);
      return await r.json();
    } finally { clearTimeout(t); }
  }

  // ---------------- DNS over HTTPS ----------------
  const DOH = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"];
  const TYPES = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, DS: 43, CAA: 257 };
  async function doh(name, type, googleOnly) {
    for (const base of googleOnly ? DOH.slice(0, 1) : DOH) {
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const j = await getJSON(`${base}?name=${encodeURIComponent(name)}&type=${type}`, 15000,
            { accept: "application/dns-json" });
          const c = Array.isArray(j.Comment) ? j.Comment.join(" ") : (j.Comment || "");
          return { rc: j.Status, ans: (j.Answer || []).map((a) => ({ type: a.type, data: a.data })), ad: j.AD, comment: c };
        } catch (e) { await sleep(400 * (attempt + 1)); }
      }
    }
    return { rc: null, ans: [], ad: null, comment: "" };
  }
  const clean = (d) => String(d).replace(/"\s*"/g, "").replace(/^"|"$/g, "");
  async function txt(name) {
    return (await doh(name, "TXT")).ans.filter((a) => a.type === 16).map((a) => clean(a.data));
  }

  // ---------------- certificate transparency ----------------
  async function ctNames(root, log, fallback) {
    const names = new Set(), siblings = {};
    const take = (list) => {
      const regs = new Set();
      for (let n of list) {
        n = String(n).toLowerCase().replace(/^\*\./, "").trim();
        if (!n || n.includes("@") || !isDomain(n)) continue; // drop email SANs (PDPO)
        if (n === root || n.endsWith("." + root)) names.add(n);
        else regs.add(registrable(n));
      }
      for (const r of regs) siblings[r] = (siblings[r] || 0) + 1;
    };
    for (let attempt = 0; attempt < 2 && !names.size; attempt++) {
      try {
        log(`crt.sh: querying %.${root}` + (attempt ? " (retry)" : ""));
        const rows = await getJSON(`https://crt.sh/?q=%25.${root}&output=json`, 90000);
        for (const r of rows) take(String(r.name_value).split("\n"));
        log(`crt.sh: ${rows.length} certificates, ${names.size} names under ${root}`, "ok");
      } catch (e) { log(`crt.sh: ${e.message || "failed"}`, "warn"); await sleep(3000); }
    }
    if (!names.size) {
      try {
        log(`certspotter: querying ${root}`);
        let after = "";
        for (let page = 0; page < 6; page++) {
          const rows = await getJSON(`https://api.certspotter.com/v1/issuances?domain=${root}&include_subdomains=true&expand=dns_names${after}`, 30000);
          if (!rows.length) break;
          for (const r of rows) take(r.dns_names || []);
          after = "&after=" + rows[rows.length - 1].id;
        }
        log(`certspotter: ${names.size} names under ${root}`, names.size ? "ok" : "warn");
      } catch (e) { log(`certspotter: ${e.message || "failed"}`, "warn"); }
    }
    let source = "live";
    if (!names.size && fallback && fallback.length) {
      fallback.filter((n) => n === root || n.endsWith("." + root)).forEach((n) => names.add(n));
      source = "snapshot";
      log(`CT sources unavailable; using the 29 Oct snapshot for ${root} (${names.size} names)`, "warn");
    }
    return { names, siblings, source };
  }

  // ---------------- hosting attribution ----------------
  let AWS = null;
  const ip2int = (ip) => ip.split(".").reduce((a, o) => (a * 256) + Number(o), 0);
  async function loadAws(log) {
    if (AWS) return AWS;
    try {
      const j = await getJSON("https://ip-ranges.amazonaws.com/ip-ranges.json", 30000);
      AWS = j.prefixes.filter((p) => p.service !== "AMAZON").map((p) => {
        const [net, len] = p.ip_prefix.split("/"); const L = Number(len);
        const size = 2 ** (32 - L); const start = Math.floor(ip2int(net) / size) * size;
        return [start, size, L, p.service, p.region];
      });
      log(`AWS ip-ranges: ${AWS.length} service prefixes loaded`, "ok");
    } catch (e) { AWS = []; log("AWS ip-ranges unavailable; service mapping skipped", "warn"); }
    return AWS;
  }
  function isPrivate(ip) {
    return /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip);
  }
  function awsService(ip) {
    const x = ip2int(ip); let best = null;
    for (const p of AWS || []) if (x >= p[0] && x < p[0] + p[1] && (!best || p[2] > best[2])) best = p;
    if (!best) return isPrivate(ip) ? "private" : "";
    return `${best[3]}@${best[4]}`;
  }
  const asnCache = new Map();
  async function asn(ip) {
    if (!asnCache.has(ip)) {
      asnCache.set(ip, (async () => {
        const t = await txt(ip.split(".").reverse().join(".") + ".origin.asn.cymru.com");
        const num = t.length ? t[0].split("|")[0].trim().split(/\s+/)[0] : "";
        const d = num ? await txt(`AS${num}.asn.cymru.com`) : [];
        return d.length ? `AS${num} ${d[0].split("|").pop().trim()}` : "";
      })());
    }
    return asnCache.get(ip);
  }

  async function resolve(name) {
    const r = await doh(name, "A");
    const cnames = r.ans.filter((a) => a.type === 5).map((a) => a.data.replace(/\.$/, ""));
    const ips = r.ans.filter((a) => a.type === 1).map((a) => a.data);
    let status = { 0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN" }[r.rc] || String(r.rc);
    if (r.rc === 0 && !r.ans.length) status = "NODATA";
    let lame = false;
    if (r.rc === 2) { // SERVFAIL: is the delegation lame (dangling NS)?
      const ns = await doh(name, "NS", true);
      lame = (ns.comment || r.comment).toLowerCase().includes("lame delegation");
    }
    const svc = ips.length ? awsService(ips[0]) : "";
    let ingress = svc.includes("CLOUDFRONT") ? "CloudFront" : svc.includes("GLOBALACC") ? "Global Accelerator"
      : svc.startsWith("EC2") ? "AWS direct (ELB/EC2/API GW)" : "";
    const owner = ips.length ? await asn(ips[0]) : "";
    if (!ingress && ips.length) ingress = owner.split(" ").slice(1).join(" ").slice(0, 40);
    let dmarc = "", spf = "";
    if (r.rc !== 3) {
      const [d, t] = await Promise.all([txt("_dmarc." + name), txt(name)]);
      dmarc = d.find((x) => x.startsWith("v=DMARC1")) || "";
      spf = t.find((x) => x.startsWith("v=spf1")) || "";
    }
    const chain = cnames.join(" > ");
    return { name, status, cname_chain: chain, ips: ips.join(" "), asn: owner, aws_service: svc, ingress,
      public_data_endpoint: /redshift|rds\.|aurora|opensearch|es\.amazonaws|elasticache|docdb|mongodb\.net/.test(chain),
      dangling_cname: cnames.length > 0 && !ips.length, lame_delegation: lame, own_dmarc: dmarc, spf };
  }

  // ---------------- email and DNS posture ----------------
  async function spfLookups(domain, seen = new Set()) {
    if (seen.has(domain)) return 0; seen.add(domain);
    let n = 0;
    for (const rec of (await txt(domain)).filter((t) => t.startsWith("v=spf1"))) {
      for (const term of rec.split(/\s+/).slice(1)) {
        const t = term.replace(/^[+\-~?]/, "");
        if (/^(include:|redirect=)/.test(t)) n += 1 + await spfLookups(t.split(/[:=]/).slice(1).join(":"), seen);
        else if (["a", "mx", "ptr"].includes(t.split(":")[0]) || t.startsWith("exists:")) n += 1;
      }
    }
    return n;
  }
  async function emailPosture(d) {
    const [mx, all, dm, sts, rpt, bimi, caa, ds, ns, lookups] = await Promise.all([
      doh(d, "MX"), txt(d), txt("_dmarc." + d), txt("_mta-sts." + d), txt("_smtp._tls." + d),
      txt("default._bimi." + d), doh(d, "CAA"), doh(d, "DS"), doh(d, "NS"), spfLookups(d)]);
    const dkim = {};
    await Promise.all(Object.entries(DKIM_SELECTORS).map(async ([s, v]) => {
      if ((await txt(`${s}._domainkey.${d}`)).length) dkim[s] = v;
    }));
    const out = {
      mx: mx.ans.filter((a) => a.type === 15).map((a) => a.data),
      spf: all.filter((t) => t.startsWith("v=spf1")),
      dmarc: dm.filter((t) => t.startsWith("v=DMARC1")),
      mta_sts: sts, tls_rpt: rpt, bimi,
      caa: caa.ans.filter((a) => a.type === 257).map((a) => a.data),
      ds: ds.ans.filter((a) => a.type === 43).map((a) => a.data),
      ns: ns.ans.filter((a) => a.type === 2).map((a) => a.data.replace(/\.$/, "")),
      spf_lookups: lookups, dkim,
      verification_txt: uniq(all.filter((t) => /verif/i.test(t) || /^(MS=|mgverify)/.test(t))
        .map((t) => t.split("=")[0])).sort(),
    };
    out.bimi_has_vmc = out.bimi.some((b) => b.includes("a="));
    return out;
  }

  // ---------------- registration (RDAP in browser; .hk WHOIS via server) ----------------
  // RDAP base per TLD from the IANA bootstrap (CORS enabled); rdap.org as a fallback.
  let BOOT = null;
  async function rdap(d) {
    if (!BOOT) BOOT = getJSON("https://data.iana.org/rdap/dns.json", 20000).catch(() => ({ services: [] }));
    const tld = d.split(".").pop();
    const svc = (await BOOT).services.find(([tlds]) => tlds.includes(tld));
    const bases = [...(svc ? svc[1] : []), "https://rdap.org/"];
    for (const base of bases) {
      try { return await getJSON(`${base.replace(/\/$/, "")}/domain/${d}`, 25000); } catch (e) { /* next */ }
    }
    throw new Error("RDAP unavailable");
  }
  async function registration(d, api, whoisFallback) {
    if (d.endsWith(".hk")) {
      if (!api) return whoisFallback && whoisFallback[d]
        ? Object.assign({ source: "HKIRC WHOIS, 29 Oct 2026" }, whoisFallback[d])
        : { note: "HKIRC WHOIS needs the server function" };
      try { return await getJSON(`${api}/whois?d=${encodeURIComponent(d)}`, 45000); }
      catch (e) { return { note: "HKIRC WHOIS unavailable" }; }
    }
    try {
      const j = await rdap(d);
      const ev = {}; (j.events || []).forEach((e) => { ev[e.eventAction] = String(e.eventDate).slice(0, 10); });
      let registrar = "";
      for (const e of j.entities || []) if ((e.roles || []).includes("registrar"))
        for (const v of (e.vcardArray || [null, []])[1]) if (v[0] === "fn") registrar = v[3];
      return { registrar, created: ev.registration || "", expires: ev.expiration || "" };
    } catch (e) { return { note: "not registered or RDAP unavailable" }; }
  }

  function lookalikeCandidates(primary) {
    const token = primary.split(".")[0];
    const set = new Set();
    for (const s of ["insurance", "life", "pay", "care", "hk", "group", "app", "login", "secure", "support", "online", "medical"])
      set.add(`${token}${s}.com`);
    for (let i = 0; i < token.length; i++) set.add(token.slice(0, i) + token.slice(i + 1) + ".com");
    for (let i = 0; i < token.length - 1; i++)
      set.add(token.slice(0, i) + token[i + 1] + token[i] + token.slice(i + 2) + ".com");
    const glyph = { o: "0", i: "1", l: "1", e: "3", b: "p", w: "vv", m: "rn" };
    for (let i = 0; i < token.length; i++) if (glyph[token[i]])
      set.add(token.slice(0, i) + glyph[token[i]] + token.slice(i + 1) + ".com");
    for (const t of ["com", "net", "co", "io", "org"]) set.add(`${token}.${t}`);
    set.delete(primary);
    return [...set].filter(isDomain).slice(0, 48);
  }

  // ---------------- orchestration ----------------
  async function collect(primary, opts = {}) {
    const log = opts.log || (() => {});
    const api = opts.api || null;
    primary = primary.toLowerCase().trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
    if (!isDomain(primary)) throw new Error("Enter a domain such as bowtie.com.hk");
    const preset = PRESETS[primary];
    const brand = uniq([primary, ...(preset ? preset.brand : []), ...(opts.siblings || [])].filter(isDomain));
    const ctRoots = preset ? preset.ctRoots : brand.filter((d) => registrable(d) === d);
    const related = uniq([...(preset ? preset.related : []), ...(opts.related || [])].filter((d) => isDomain(d) && !brand.includes(d)));
    log(`Scope: ${brand.join(", ")}` + (related.length ? `; related (DNS only): ${related.join(", ")}` : ""));
    log(preset ? "Using the agreed Task A scope for this domain" : "No preset; using the domains you entered");

    const t0 = Date.now();
    const names = new Set([...brand, ...(preset ? preset.extra : [])]);
    const siblings = {}; let ctSource = "live";
    for (const root of ctRoots) {
      const r = await ctNames(root, log, opts.fallbackNames);
      r.names.forEach((n) => names.add(n));
      Object.entries(r.siblings).forEach(([k, v]) => { siblings[k] = (siblings[k] || 0) + v; });
      if (r.source !== "live") ctSource = r.source;
    }
    await loadAws(log);
    const CAP = 800; // keeps a browser scan near two minutes; larger estates belong in recon.py
    let list = [...names].sort();
    if (list.length > CAP) {
      log(`${list.length} names found; resolving the ${CAP} shortest (closest to the root) to keep the scan passive and quick`, "warn");
      list = list.sort((a, b) => a.split(".").length - b.split(".").length || a.length - b.length).slice(0, CAP).sort();
    }
    log(`Resolving ${list.length} names over DNS over HTTPS (no brute force, CT and passive names only)`);
    let done = 0;
    const hosts = await pool(list, 10, async (n) => {
      const h = await resolve(n);
      if (++done % 25 === 0 || done === list.length) log(`resolved ${done}/${list.length}`, "dim");
      if (h.public_data_endpoint) log(`public data endpoint: ${n}`, "bad");
      if (h.lame_delegation) log(`lame delegation: ${n}`, "bad");
      if (h.dangling_cname) log(`dangling CNAME: ${n}`, "bad");
      return h;
    });

    log("Email posture: MX, SPF, DMARC, DKIM (vendor selectors only), MTA-STS, TLS-RPT, BIMI, CAA, DNSSEC");
    const email = {};
    for (const d of [...brand, ...related]) { email[d] = await emailPosture(d); log(`email: ${d}`, "dim"); }

    log("Registration: RDAP" + (api ? " and HKIRC WHOIS (registrant company and dates only)" : ""));
    const registration_ = {};
    for (const d of [...brand, ...related]) registration_[d] = await registration(d, api, preset && preset.whois);
    const founded = preset ? preset.founded : String(registration_[primary].created || "").slice(0, 7) || "";

    log("Lookalikes: checking registration only, never fetching");
    let candidates = preset ? preset.lookalikes : lookalikeCandidates(primary);
    if (!preset) {
      const exists = await pool(candidates, 8, async (c) => (await doh(c, "NS")).rc === 0);
      candidates = candidates.filter((c, i) => exists[i]);
    }
    const lookalikes = await pool(candidates, 4, async (d) => {
      const r = await registration(d, api);
      return Object.assign({ domain: d }, r, { post_brand: !!(r.created && founded) && normDate(r.created).slice(0, 7) >= founded });
    });

    let web = [], hsts = {}, webNote = "";
    if (api) {
      const live = new Set(hosts.filter((h) => h.ips).map((h) => h.name));
      const hs = (preset ? preset.httpHosts : ["www", ""]).filter((l) => live.has(l ? `${l}.${primary}` : primary));
      log(`HTTP: one GET each, no redirects followed, to ${hs.map((l) => l ? l + "." + primary : primary).join(", ")} and security.txt`);
      try {
        const j = await getJSON(`${api}/web?domain=${primary}&hosts=${hs.join(",")}`, 60000);
        web = j.web || []; hsts = j.hsts || {};
      } catch (e) { webNote = "Header checks unavailable: " + e.message; log(webNote, "warn"); }
    } else { webNote = "Header checks need the server function (deploy with /api)"; log(webNote, "warn"); }

    const overrides = {};
    hosts.forEach((h) => { if (h.own_dmarc && !brand.includes(h.name) && !related.includes(h.name)) overrides[h.name] = h.own_dmarc; });
    log(`Done in ${Math.round((Date.now() - t0) / 1000)} s`, "ok");
    return { meta: { domain: primary, collected: new Date().toISOString(), mode: "live", ctSource, webNote },
      scope: { brand, ctRoots, related, founded, preset: !!preset, sector: preset ? preset.sector : "" },
      hosts, email, registration: registration_, dmarc_overrides: overrides, hsts_preload: hsts, web, lookalikes,
      ct_siblings: siblings };
  }
  function normDate(s) { // HKIRC uses DD-MM-YYYY
    const m = String(s).match(/^(\d{2})-(\d{2})-(\d{4})$/); return m ? `${m[3]}-${m[2]}-${m[1]}` : String(s);
  }

  // ---------------- analysis: turns data into the Task A sections ----------------
  const VENDOR_RULES = [
    // [vendor, where, regex, strength]
    ["AWS", "cname", /amazonaws\.com|cloudfront\.net|awsglobalaccelerator/, "Infrastructure"],
    ["AWS", "ns", /awsdns/, "Infrastructure"],
    ["Cloudflare", "ns", /cloudflare\.com/, "Infrastructure"],
    ["Cloudflare", "mx", /mxrecord\.(io|mx)/, "Infrastructure"],
    ["Cloudflare", "asn", /^AS13335 /, "Infrastructure"],
    ["Google Workspace", "spf", /_spf\.google\.com/, "Infrastructure"],
    ["Google Workspace", "mx", /google(mail)?\.com/, "Infrastructure"],
    ["Google Workspace", "dkim", /^google$/, "Infrastructure"],
    ["Microsoft 365", "spf", /spf\.protection\.outlook\.com/, "Infrastructure"],
    ["Microsoft 365", "mx", /mail\.protection\.outlook\.com/, "Infrastructure"],
    ["Zendesk", "cname", /zendesk\.com/, "Infrastructure"],
    ["Zendesk", "spf", /mail\.zendesk\.com/, "Infrastructure"],
    ["Zendesk", "dkim", /^zendesk/, "Infrastructure"],
    ["Mailgun", "spf", /mailgun\.org/, "Infrastructure"],
    ["Mailchimp", "spf", /mcsv\.net|mailchimp/, "Infrastructure"],
    ["SendGrid", "spf", /sendgrid\.net/, "Infrastructure"],
    ["Amazon SES", "spf", /amazonses\.com/, "Infrastructure"],
    ["KnowBe4", "spf", /knowbe4\.com/, "Infrastructure"],
    ["Postmark", "dmarc", /postmarkapp\.com/, "Infrastructure"],
    ["Salesforce", "spf", /salesforce\.com/, "Infrastructure"],
    ["HubSpot", "spf", /hubspotemail\.net/, "Infrastructure"],
    ["Webflow", "cname", /webflow\.(com|io)/, "Infrastructure"],
    ["Teamtailor", "cname", /teamtailor/, "Infrastructure"],
    ["GitHub Pages", "cname", /github\.io/, "Infrastructure"],
    ["Fastly", "asn", /^AS54113 /, "Infrastructure"],
    ["Google Cloud", "asn", /^AS(15169|396982) /, "Infrastructure"],
    ["Vercel", "cname", /vercel-dns|vercel\.app/, "Infrastructure"],
    ["Netlify", "cname", /netlify/, "Infrastructure"],
    ["Heroku", "cname", /herokudns|herokuapp/, "Infrastructure"],
    ["Okta", "cname", /okta\.com/, "Infrastructure"],
    ["Statuspage", "cname", /stspg-customer/, "Infrastructure"],
    ["Statsig", "page", /statsig/, "Live page"],
    ["Mixpanel", "page", /mixpanel|mxpnl/, "Live page"],
    ["HubSpot", "page", /hubspot|hsforms|hscollectedforms/, "Live page"],
    ["Cobrowse.io", "page", /cobrowse\.io/, "Live page"],
    ["Calendly", "page", /calendly/, "Live page"],
    ["Sentry", "page", /sentry\.io/, "Live page"],
    ["Zendesk", "page", /zdassets|zopim|zendesk/, "Live page"],
    ["Google Tag Manager", "page", /googletagmanager/, "Live page"],
    ["Meta Pixel", "page", /facebook\.(com|net)\/tr|connect\.facebook/, "Live page"],
    ["LinkedIn Insight", "page", /linkedin\.oribi|px\.ads\.linkedin/, "Live page"],
    ["Hotjar", "page", /hotjar/, "Live page"],
    ["Segment", "page", /segment\.(com|io)/, "Live page"],
    ["Intercom", "page", /intercom/, "Live page"],
  ];
  const VERIF = { MS: "Microsoft", "apple-domain-verification": "Apple", "atlassian-domain-verification": "Atlassian",
    "facebook-domain-verification": "Meta", "figma-domain-verification": "Figma", "google-site-verification": "Google Search Console",
    mgverify: "Mailgun", "mixpanel-domain-verify": "Mixpanel", "slack-domain-verification": "Slack",
    "stripe-verification": "Stripe", "twilio-domain-verification": "Twilio", "yahoo-verification-key": "Yahoo",
    "docusign": "DocuSign", "adobe-idp-site-verification": "Adobe", "zoom-domain-verification": "Zoom",
    "domain-verification": "Unnamed vendor (generic token)", "knowbe4-site-verification": "KnowBe4",
    "openai-domain-verification": "OpenAI", "anthropic-domain-verification": "Anthropic", "notion-domain-verification": "Notion" };

  function dmarcPolicy(rec) { const m = /(?:^|;)\s*p=(\w+)/.exec(rec || ""); return m ? m[1] : ""; }
  function dmarcSub(rec) { const m = /(?:^|;)\s*sp=(\w+)/.exec(rec || ""); return m ? m[1] : ""; }
  function spfAll(rec) { const m = /([~?+-])all\b/.exec(rec || ""); return m ? m[1] + "all" : rec ? "no all" : ""; }
  const short = (h, d) => h.replace("." + d, "");

  function analyze(R) {
    const D = R.meta.domain;
    const hosts = R.hosts.map((h) => Object.assign({}, h, { env: envOf(h.name), ingress: normIngress(h.ingress) }));
    const live = hosts.filter((h) => h.ips);
    const byIngress = {};
    live.forEach((h) => { const k = h.ingress || "Unknown"; byIngress[k] = (byIngress[k] || 0) + 1; });
    const nonprod = live.filter((h) => h.env !== "prod");
    const dataEps = hosts.filter((h) => h.public_data_endpoint);
    const lame = hosts.filter((h) => h.lame_delegation);
    const dangling = hosts.filter((h) => h.dangling_cname);
    const accountIds = uniq(hosts.flatMap((h) => (h.cname_chain.match(/\.(\d{12})\./g) || []).map((x) => x.slice(1, 5) + "****" + x.slice(9, 13))));
    const reg = R.registration[D] || {};

    // Domains and attribution
    const linked = new Set(((R.web.find((w) => /\/\/www\./.test(w.url) && w.third_party_hosts) || {}).third_party_hosts || []).map(registrable));
    const pNS = (R.email[D] || {}).ns || [];
    const nsProv = (ns) => uniq(ns.map((n) => /awsdns/.test(n) ? "Route 53" : /cloudflare/.test(n) ? "Cloudflare" : registrable(n)));
    const domains = [...R.scope.brand, ...R.scope.related].map((d) => {
      const r = R.registration[d] || {}, e = R.email[d] || {};
      const ev = []; let conf = "Unconfirmed";
      const sameCo = r.registrant_company && reg.registrant_company && r.registrant_company === reg.registrant_company;
      const sameRar = r.registrar && reg.registrar && r.registrar === reg.registrar;
      if (d === D) { ev.push(r.registrant_company ? `Registrant ${r.registrant_company}` : "Primary domain entered"); conf = "Confirmed"; }
      else if (sameCo) { ev.push("Same registrant company"); conf = "Confirmed"; }
      if (r.registrar) ev.push(`${r.registrar.replace(/,? Inc\.?$/, "")} registrar${sameRar && d !== D ? " (same as primary)" : ""}`);
      if (linked.has(d)) ev.push("linked from the official homepage");
      if (R.ct_siblings && R.ct_siblings[d]) ev.push(`shares ${R.ct_siblings[d]} certificate(s) with the primary`);
      const shared = nsProv(e.ns || []).filter((p) => nsProv(pNS).includes(p));
      if (shared.length && d !== D) ev.push(`${shared.join(", ")} DNS`);
      if ((e.spf || []).some((s) => /_spf\.google\.com/.test(s)) && d !== D) ev.push("Google SPF");
      if (conf === "Unconfirmed") {
        if (sameRar && (linked.has(d) || (R.ct_siblings || {})[d])) conf = "High";
        else if (sameRar && shared.length) { conf = "Probable"; if (!r.registrant_company) ev.push("registrant redacted; not linked"); }
        else if (linked.has(d)) conf = "High";
      }
      return { domain: d, created: normDate(r.created || "").slice(0, 4), evidence: ev.join("; "), confidence: conf };
    });
    (R.lookalikes || []).filter((l) => l.created && !l.post_brand).forEach((l) =>
      domains.push({ domain: l.domain, created: normDate(l.created).slice(0, 4), evidence: `Different registrar; registered ${normDate(l.created).slice(0, 4)}, before the brand existed`, confidence: "Not attributed" }));

    // Subdomain groups
    const groups = [];
    const pick = (re) => live.filter((h) => re.test(h.name)).map((h) => h.name);
    const g = (label, re) => { const n = pick(re); if (n.length) groups.push({ label, names: n }); };
    g("Per pull request previews", /(^|\.)pr-/);
    g("Regional APIs", /^(sg|jp|hk|us|eu|au|my|th)\.api\./);
    g("DR endpoints", /(^|\.)dr\./);
    g("Admin and auth", /(^|\.)(admin|auth)\./);
    g("Remote access", /(^|\.)(openvpn|vpn|vdi|citrix|bastion)\./);
    g("AI and MCP gateways", /(llm|mcp|gpt)/);
    g("Workplace tools", /^(hotdesk|room|orgchart|reimburse)\./);

    // Vendors
    const vmap = new Map();
    const add = (v, s, ev) => { if (!vmap.has(v)) vmap.set(v, { vendor: v, strength: s, evidence: new Set() });
      const o = vmap.get(v); o.evidence.add(ev);
      const rank = { Infrastructure: 3, "Live page": 2, Attested: 1 }; if (rank[s] > rank[o.strength]) o.strength = s; };
    const pageText = R.web.map((w) => [(w.security_headers || {})["content-security-policy"] || "", (w.third_party_hosts || []).join(" "), (w.external_scripts || []).join(" ")].join(" ")).join(" ");
    for (const [v, where, re, s] of VENDOR_RULES) {
      if (where === "cname") hosts.forEach((h) => { if (re.test(h.cname_chain)) add(v, s, `${short(h.name, D)} CNAME`); });
      if (where === "asn") live.forEach((h) => { if (re.test(h.asn)) add(v, s, `${short(h.name, D)} on ${h.asn.split(" ")[0]}`); });
      if (where === "page" && re.test(pageText)) add(v, s, "homepage script or CSP allowance");
      for (const [d, e] of Object.entries(R.email)) {
        if (where === "spf" && (e.spf || []).some((x) => re.test(x))) add(v, s, `SPF include on ${d}`);
        if (where === "mx" && (e.mx || []).some((x) => re.test(x))) add(v, s, `MX of ${d}`);
        if (where === "ns" && (e.ns || []).some((x) => re.test(x))) add(v, s, `NS of ${d}`);
        if (where === "dkim" && Object.keys(e.dkim || {}).some((x) => re.test(x))) add(v, s, `DKIM ${Object.keys(e.dkim).filter((x) => re.test(x)).join("/")} on ${d}`);
        if (where === "dmarc" && (e.dmarc || []).some((x) => re.test(x))) add(v, s, `DMARC reports on ${d}`);
      }
      if (where === "spf") hosts.forEach((h) => { if (!R.email[h.name] && re.test(h.spf || "")) add(v, s, `SPF on ${short(h.name, D)}`); });
      if (where === "dmarc") Object.entries(R.dmarc_overrides).forEach(([n, x]) => { if (re.test(x)) add(v, s, `DMARC reports on ${short(n, D)}`); });
    }
    for (const [d, e] of Object.entries(R.email)) for (const k of e.verification_txt || []) {
      const v = VERIF[k] || k; if (!vmap.has(v)) add(v, "Attested", `verification TXT on ${d}`); else vmap.get(v).evidence.add(`verification TXT on ${d}`);
    }
    const vendors = [...vmap.values()].map((o) => {
      const ev = [...o.evidence]; return { vendor: o.vendor, strength: o.strength, evidence: ev.slice(0, 4).join("; ") + (ev.length > 4 ? `; +${ev.length - 4} more` : "") };
    }).sort((a, b) => ({ Infrastructure: 0, "Live page": 1, Attested: 2 }[a.strength] - { Infrastructure: 0, "Live page": 1, Attested: 2 }[b.strength]) || a.vendor.localeCompare(b.vendor));
    const zendeskDouble = vmap.has("Zendesk") && [...vmap.get("Zendesk").evidence].some((x) => /SPF/.test(x)) && [...vmap.get("Zendesk").evidence].some((x) => /DKIM/.test(x));

    // Email
    const emailRows = Object.entries(R.email).map(([d, e]) => {
      const dm = e.dmarc[0] || "";
      return { domain: d, mx: e.mx.length ? mxLabel(e.mx) : "None", spf: e.spf[0] ? spfAll(e.spf[0]) + ` (${e.spf_lookups} lookups)` : "None",
        dmarc: dm ? `p=${dmarcPolicy(dm)}${dmarcSub(dm) ? "; sp=" + dmarcSub(dm) : ""}` : "None",
        dmarcState: !dm ? "bad" : dmarcPolicy(dm) === "reject" ? "good" : dmarcPolicy(dm) === "quarantine" ? "warn" : "bad",
        dkim: Object.keys(e.dkim).join(", ") || "None found (vendor selectors only)",
        mtasts: e.mta_sts.length ? "Yes" : "No", tlsrpt: e.tls_rpt.length ? "Yes" : "No",
        dnssec: e.ds.length ? "Yes" : "No", caa: e.caa.length ? "Yes" : "No",
        bimi: e.bimi.length ? (e.bimi_has_vmc ? "Yes, with VMC" : "Present, no VMC") : "No",
        receivesMail: e.mx.length > 0 };
    });
    const noDmarc = emailRows.filter((r) => r.dmarc === "None").map((r) => r.domain);
    const weakDmarc = emailRows.filter((r) => /p=none/.test(r.dmarc)).map((r) => r.domain);
    const overrideNone = Object.entries(R.dmarc_overrides).filter(([, v]) => dmarcPolicy(v) === "none").map(([k]) => k);
    const primaryDmarc = (R.email[D] || { dmarc: [] }).dmarc[0] || "";
    const softSpfOverride = hosts.filter((h) => R.dmarc_overrides[h.name] && /\?all/.test(h.spf || "")).map((h) => h.name);
    const attackerPaths = [];
    if (!primaryDmarc || dmarcPolicy(primaryDmarc) === "none")
      attackerPaths.push(`<b>${D}</b> itself has ${primaryDmarc ? "DMARC p=none" : "no DMARC"}, so mail forged from the primary domain is delivered.`);
    else attackerPaths.unshift(`Spoofing <b>${D}</b> itself is blocked (p=${dmarcPolicy(primaryDmarc)}).`);
    noDmarc.filter((d) => d !== D).forEach((d) => {
      const used = hosts.filter((h) => h.ips && h.name.endsWith("." + d)).length;
      attackerPaths.push(`<b>${d}</b> ${R.email[d].mx.length ? "receives mail and " : ""}has no DMARC${used ? ` while serving ${used} live hosts` : ""}, so mail claiming to be from it gets no policy.`);
    });
    if (overrideNone.length) attackerPaths.push(`<b>${overrideNone.map((n) => short(n, D)).join(", ")}</b> publish their own <code>p=none</code>, which overrides the apex <code>sp=</code>. A forged message from these names is not blocked.`);
    if (softSpfOverride.length) attackerPaths.push(`<b>${softSpfOverride.map((n) => short(n, D)).join(", ")}</b> ${softSpfOverride.length > 1 ? "combine" : "combines"} p=none with SPF <code>?all</code>.`);
    if (!emailRows.some((r) => r.mtasts === "Yes")) attackerPaths.push("No MTA-STS anywhere, so inbound TLS can be stripped by anyone on the network path.");
    const payoff = R.scope.sector === "insurer"
      ? "For an insurer the payoff is not the email but what follows: member account takeover leading to fraudulent claims or bank detail changes."
      : "The payoff is what follows the email: credential phishing, invoice and payment redirection, and account takeover.";

    // Edge
    const cdnFront = live.some((h) => /CloudFront|Cloudflare|Fastly|Akamai|Imperva/i.test(h.ingress) && h.env === "prod");
    const rank = (h) => (h.name.endsWith("." + D) ? 4 : 0) + (/^(sg|jp|hk|alb)\.api\.|^mb\./.test(h.name) ? 2 : /api|^hooks|^kb|^zd/.test(h.name) ? 1 : 0);
    const bypass = live.filter((h) => h.env === "prod" && /AWS direct/.test(h.ingress) && !/blog/.test(h.name))
      .sort((a, b) => rank(b) - rank(a) || a.name.length - b.name.length);
    const webBy = (lbl) => R.web.find((w) => { try { return new URL(w.url).hostname === (lbl ? `${lbl}.${D}` : D) && !/security\.txt/.test(w.url); } catch (e) { return false; } });
    const headerIssues = [];
    const api_ = webBy("api"), app_ = webBy("app"), www_ = webBy("www"), apex_ = webBy("");
    if (api_ && !Object.keys(api_.security_headers || {}).length) headerIssues.push({ host: `api.${D}`, text: "returns no HSTS, CSP or nosniff" });
    const discl = R.web.filter((w) => Object.keys(w.disclosure_headers || {}).some((k) => /release|commit|version|x-powered-by/.test(k)));
    discl.forEach((w) => headerIssues.push({ host: new URL(w.url).hostname, text: `publishes ${Object.keys(w.disclosure_headers).filter((k) => /release|commit|version|powered/.test(k)).map((k) => "<code>" + k + "</code>").join(" and ")}, so anyone can see which build is deployed` }));
    if (app_ && app_.csp_mode === "report-only") headerIssues.push({ host: `app.${D}`, text: "ships its CSP as <b>report-only</b>, so it enforces nothing" });
    if (app_ && app_.csp_mode === "none") headerIssues.push({ host: `app.${D}`, text: "sends no CSP" });
    if (www_ && www_.csp_script_src_permissive) headerIssues.push({ host: `www.${D}`, text: "enforces a CSP, but <code>script-src</code> allows any <code>https:</code> source plus <code>unsafe-inline</code> and <code>unsafe-eval</code>" });
    if (www_ && www_.csp_mode === "none" && www_.status && www_.status < 400) headerIssues.push({ host: `www.${D}`, text: "sends no CSP" });
    const noSri = (www_ && www_.external_scripts_without_sri) || [];
    const unpinned = noSri.filter((s) => /cdn\.jsdelivr\.net\/npm\/[^@/]+\/|unpkg\.com\/[^@/]+\//.test(s));
    if (unpinned.length) headerIssues.push({ host: `www.${D}`, text: `loads ${unpinned.map((s) => "<code>" + esc((s.split("/npm/")[1] || s).split("/")[0]) + "</code>").join(", ")} from a public CDN <b>unpinned and without SRI</b>; a compromised package would run on the page` });
    const apexNoHsts = apex_ && !(apex_.security_headers || {})["strict-transport-security"];
    const sectxt = R.web.find((w) => /security\.txt/.test(w.url));
    const sectxtMissing = sectxt ? (sectxt.status === 200 ? ["Expires", "Policy"].filter((f) => !(sectxt.securitytxt_fields || []).includes(f)) : ["file"]) : null;
    const goods = [];
    if (cdnFront) goods.push("CDN in front of the main " + ["www", "app", "api"].filter((l) => live.some((h) => h.name === `${l}.${D}` && /CloudFront|Cloudflare|Fastly/.test(h.ingress))).join(", "));
    if (app_ && (app_.security_headers || {})["x-frame-options"]) goods.push(`X-Frame-Options ${(app_.security_headers || {})["x-frame-options"]} on the app`);
    if (dmarcPolicy(primaryDmarc) === "reject") goods.push("DMARC reject on the primary");
    if (live.some((h) => /Cloudflare/.test(h.ingress) && /(llm|mcp|gpt)/.test(h.name))) goods.push("Cloudflare in front of the AI gateways");

    // Risks (scored; the top five are ranked by attacker value against ease)
    const risks = [];
    const nm = (a, n = 4) => a.slice(0, n).map((h) => "<code>" + short(h.name || h, D) + "</code>").join(", ") + (a.length > n ? ` and ${a.length - n} more` : "");
    const prPreviews = live.filter((h) => /(^|\.)pr-/.test(h.name)).length;
    if (dataEps.length || nonprod.length >= 10) risks.push({ score: dataEps.length ? 95 : 70,
      title: dataEps.length ? `Public data endpoints and a ${nonprod.length} host non production estate` : `A ${nonprod.length} host non production and internal estate is public`,
      detail: (dataEps.length ? `${nm(dataEps)} resolve to internet facing database or warehouse endpoints. ` : "") +
        `${nonprod.length} of ${live.length} live names are non production, internal, admin or remote access${prPreviews ? `, including ${prPreviews} per pull request previews` : ""}. Staging often holds copied customer data, which would make this a PDPO${R.scope.sector === "insurer" ? " and GL20" : ""} issue.`,
      fix: (dataEps.length ? "Make the load balancers internal and set data stores to not publicly accessible; reach them via SSM or Client VPN. " : "") +
        "Move non production behind an identity aware proxy (Cloudflare Access or similar). Add an AWS Config rule and a CI gate that fails any public non production record. Confirm no production PII is in dev.",
      cost: "6 to 10 days, ~HK$30k; Access ~HK$600 per user per year if more seats needed" });
    const emailGaps = noDmarc.length + weakDmarc.length + overrideNone.length;
    const postBrand = (R.lookalikes || []).filter((l) => l.post_brand);
    if (emailGaps) risks.push({ score: (!primaryDmarc || dmarcPolicy(primaryDmarc) === "none") ? 97 : 85,
      title: (!primaryDmarc || dmarcPolicy(primaryDmarc) === "none") ? "The primary domain can be spoofed" : "Email trust stops at the apex",
      detail: [noDmarc.length ? `${noDmarc.join(" and ")} ${noDmarc.length > 1 ? "have" : "has"} no DMARC` : "", weakDmarc.length ? `${weakDmarc.join(", ")} at p=none` : "",
        overrideNone.length ? `${nm(overrideNone)} override to <code>p=none</code>` : "", postBrand.length ? `${postBrand.length} post brand lookalikes registered` : ""].filter(Boolean).join("; ") + ".",
      fix: `Publish DMARC on ${noDmarc.length ? noDmarc.join(" and ") : "every domain"} (p=none for 2 weeks using the existing aggregate reports, then reject). Remove or tighten the overrides once senders align. Add MTA-STS and TLS-RPT.${postBrand.length ? " Subscribe to lookalike monitoring and refer the post brand names to counsel." : ""}`,
      cost: "3 to 5 days plus a 4 week watch, ~HK$20k; monitoring HK$20k to 40k a year" });
    if (bypass.length && cdnFront) risks.push({ score: 75, title: "CDN and WAF bypass",
      detail: `${nm(bypass, 5)} answer directly on AWS load balancers, EC2 or API Gateway while the main hosts sit behind a CDN. If WAF is attached only at the CDN, these paths skip it.`,
      fix: "Restrict ALB security groups to the CloudFront managed prefix list plus an origin secret header, or attach the same WAF ACL to the ALBs and API stages. Remove public <code>alb.*</code> records.",
      cost: "4 to 6 days, ~HK$24k; WAF ~HK$1k a month" });
    if (headerIssues.length || apexNoHsts) risks.push({ score: 65, title: "Client side and header gaps on customer paths",
      detail: headerIssues.map((i) => `<code>${short(i.host, D)}</code> ${i.text}`).join("; ") + (apexNoHsts ? "; the apex redirects without HSTS" : "") + ".",
      fix: "One response header policy at the CDN for all production hosts. Pin and SRI or self host third party scripts. Tighten <code>script-src</code> with nonces, report-only first, then enforce. Strip build headers. Add HSTS on the apex and submit for preload.",
      cost: "6 to 8 days, ~HK$30k; no licence cost" });
    const noCaa = emailRows.filter((r) => r.caa === "No").length, noSec = emailRows.filter((r) => r.dnssec === "No").length;
    if (lame.length || dangling.length || noCaa || (sectxtMissing && sectxtMissing.length)) risks.push({ score: dangling.length ? 88 : lame.length ? 55 : 35,
      title: dangling.length ? "Dangling DNS: subdomain takeover candidates" : "DNS and certificate hygiene",
      detail: [dangling.length ? `${nm(dangling)} CNAME to targets that no longer exist` : "", lame.length ? `${nm(lame)} delegated to nameservers that refuse the zone (lame delegation, hijack candidate)` : "",
        noCaa ? `no CAA on ${noCaa} of ${emailRows.length} domains` : "", noSec ? `no DNSSEC on ${noSec}` : "",
        sectxtMissing && sectxtMissing.length ? `security.txt ${sectxtMissing[0] === "file" ? "missing" : "lacks " + sectxtMissing.join(" and ")}` : ""].filter(Boolean).join("; ") + ".",
      fix: "Remove dangling and lame delegations; add CAA for the CAs in use; enable DNSSEC; free CT alerting; quarterly DNS ownership review; fix security.txt" + (reg.expires ? `. Confirm ${D} auto renew (expires ${esc(reg.expires)})` : "") + ".",
      cost: "2 days, ~HK$8k; no licence cost" });
    risks.sort((a, b) => b.score - a.score);

    // Limits
    const cannot = [
      dataEps.length ? `whether ${dataEps.map((h) => short(h.name, D)).join(" and ")} accept connections` : "whether exposed services accept connections",
      "whether WAF protects the direct load balancer and API Gateway hosts (a missing vendor header is not a missing WAF)",
      "whether admin, MCP and gateway hosts enforce SSO",
      "whether non production holds real customer data (the most important unknown)",
      "DKIM for senders with custom selectors, and the full sender list before tightening DMARC",
      "staff address format (deliberately not researched) and domain level breach exposure (needs owner verification)" ];
    const needAuth = [
      `TCP reachability of ${dataEps.length ? dataEps.map((h) => short(h.name, D)).join(", ") : "exposed data stores"}${live.some((h) => /openvpn/.test(h.name)) ? " and openvpn" : ""}`,
      "a direct to origin and WAF efficacy test with benign payloads",
      "HTTP to admin, staging and MCP hosts to confirm auth gating",
      lame.length || dangling.length ? `a controlled proof of the ${[...lame, ...dangling].map((h) => short(h.name, D)).slice(0, 2).join(" / ")} takeover` : "any subdomain takeover proof",
      "read only review of CDN and WAF configuration; any phishing simulation" ];

    const notable = live.filter((h) => h.public_data_endpoint || h.lame_delegation || h.dangling_cname || R.dmarc_overrides[h.name] || bypass.includes(h)
      || /^(www\.|app\.|api\.|admin\.|openvpn\.)/.test(h.name) || R.scope.brand.includes(h.name))
      .concat(hosts.filter((h) => !h.ips && (h.lame_delegation || R.dmarc_overrides[h.name])));

    return { D, hosts, live, byIngress, nonprod, dataEps, lame, dangling, accountIds, domains, groups, vendors, zendeskDouble,
      emailRows, attackerPaths, payoff, bypass, headerIssues, apexNoHsts, sectxtMissing, goods, risks: risks.slice(0, 5), cannot, needAuth,
      notable: uniq(notable), reg, postBrand, preBrand: (R.lookalikes || []).filter((l) => l.created && !l.post_brand) };
  }
  function esc(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
  function normIngress(i) {
    if (!i) return i;
    if (/cloudflare/i.test(i)) return "Cloudflare";
    if (/fastly/i.test(i)) return "Fastly";
    if (/google/i.test(i)) return "Google";
    if (/akamai/i.test(i)) return "Akamai";
    if (/incapsula|imperva/i.test(i)) return "Imperva";
    if (/microsoft/i.test(i)) return "Azure";
    return i;
  }
  function mxLabel(mx) {
    const s = mx.join(" ");
    if (/mxrecord\.(io|mx)/.test(s)) return "Cloudflare Area 1";
    if (/google/.test(s)) return "Google";
    if (/outlook/.test(s)) return "Microsoft 365";
    if (/pphosted|ppe-hosted/.test(s)) return "Proofpoint";
    if (/mimecast/.test(s)) return "Mimecast";
    return mx[0].split(" ").pop().replace(/\.$/, "");
  }

  G.ASM = { collect, analyze, PRESETS, envOf, registrable, isDomain, esc };
})(typeof window !== "undefined" ? window : globalThis);
