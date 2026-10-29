/* Renders collected data as the Task A report: sections 1 to 7 plus the host appendix. */
(function () {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const E = (s) => ASM.esc(s == null ? "" : s);
  let R = null, A = null, filter = "live", query = "";
  // Server routes for headers and .hk WHOIS: same origin by default, none on a static host,
  // or another origin named in <meta name="asm-api">.
  const META = document.querySelector('meta[name="asm-api"]');
  const API = META && META.content ? META.content.replace(/\/$/, "") : /github\.io$/.test(location.hostname) ? null : "/api";

  // ---------------- console ----------------
  const con = $("#console");
  function log(msg, level) {
    const t = new Date().toTimeString().slice(0, 8);
    const line = document.createElement("div");
    line.innerHTML = `<span class="t">[${t}]</span> <span class="${level || ""}">${E(msg)}</span>`;
    con.appendChild(line); con.scrollTop = con.scrollHeight;
  }
  function state(text, kind) { $("#state").textContent = text; $("#state-dot").className = "dot " + (kind || ""); }
  $("#toggle-console").addEventListener("click", (e) => {
    const closed = con.classList.toggle("closed");
    e.target.textContent = closed ? "Show log" : "Hide log"; e.target.setAttribute("aria-expanded", String(!closed));
  });

  // ---------------- actions ----------------
  const list = (v) => v.split(/[\s,]+/).map((x) => x.trim().toLowerCase()).filter(Boolean);
  $("#scan").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const d = $("#domain").value.trim();
    $("#run").disabled = true; $("#snap").disabled = true; con.classList.remove("closed");
    con.textContent = ""; state("Scanning " + d, "busy");
    log(`Passive scan of ${d} started. No port scans, brute force, logins or requests to non production hosts.`);
    try {
      const res = await ASM.collect(d, { log, api: API, siblings: list($("#siblings").value), related: list($("#related").value),
        fallbackNames: d.replace(/^www\./, "") === "bowtie.com.hk" ? window.SNAPSHOT_NAMES || null : null });
      show(res);
      state(`Live scan complete: ${res.hosts.length} names`, "ok");
    } catch (e) { log(e.message || String(e), "bad"); state("Scan failed", ""); }
    $("#run").disabled = false; $("#snap").disabled = false;
  });
  $("#snap").addEventListener("click", () => {
    con.textContent = ""; log("Loaded the 29 Oct 2026 collection that the Task A report was written from (recon.py output).", "ok");
    $("#domain").value = "bowtie.com.hk"; show(window.SNAPSHOT); state("Snapshot: 29 Oct 2026", "ok");
  });

  // ---------------- helpers ----------------
  const chip = (t, k) => `<span class="chip ${k || ""}">${E(t)}</span>`;
  const conf = { Confirmed: "good", High: "", Probable: "med", Unconfirmed: "mute", "Not attributed": "mute" };
  const strength = { Infrastructure: "good", "Live page": "", Attested: "mute" };
  const sev = (s) => s >= 90 ? ["Critical", "crit", "bad"] : s >= 70 ? ["High", "high", "warn"] : s >= 50 ? ["Medium", "med", "med"] : ["Low", "low", "mute"];
  const short = (n) => n.replace("." + A.D, "");
  const pct = (a, b) => b ? Math.round((100 * a) / b) : 0;
  const strip = (h) => String(h).replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
  function resolvesTo(h) {
    const c = h.cname_chain, svc = h.aws_service;
    const region = (svc.split("@")[1] || "").replace("GLOBAL", "");
    if (/redshift/.test(c)) return "Redshift Serverless, public IP";
    if (/rds\.|aurora/.test(c)) return "Internet facing NLB (database)";
    if (/elb\.amazonaws|\.elb\./.test(c)) return `Load balancer ${region}`.trim();
    if (/execute-api/.test(c)) return `API Gateway ${region}`.trim();
    if (/zendesk/.test(c)) return "Zendesk";
    if (/github\.io/.test(c)) return "GitHub Pages";
    if (/webflow/.test(c)) return "Webflow";
    if (/teamtailor/.test(c)) return "Teamtailor";
    if (h.lame_delegation) return "Lame delegation";
    if (!h.ips) return h.own_dmarc || h.spf ? "TXT only" : h.status;
    if (/CLOUDFRONT/.test(svc)) return "CloudFront";
    if (/GLOBALACC/.test(svc)) return "Global Accelerator";
    if (/^EC2/.test(svc)) return `AWS (EC2 range) ${region}`;
    return h.ingress || h.asn.split(" ")[0];
  }
  function findingsFor(h) {
    const f = [];
    if (h.public_data_endpoint) f.push(["Public data endpoint", "bad"]);
    if (h.lame_delegation) f.push(["Lame delegation", "bad"]);
    if (h.dangling_cname) f.push(["Dangling CNAME", "bad"]);
    if (h.own_dmarc && /p=none/.test(h.own_dmarc)) f.push(["Own DMARC p=none", "warn"]);
    if (A.bypass.includes(h)) f.push(["CDN bypass", "warn"]);
    A.headerIssues.filter((i) => i.host === h.name).forEach((i) => f.push([strip(i.text).split(",")[0].replace(/^(returns|publishes|ships|enforces|loads|sends) /, (m) => m), "med"]));
    if (h.name === A.D && A.apexNoHsts) f.push(["Redirect without HSTS", "med"]);
    if (h.env === "non-prod" && h.ips) f.push(["Non production exposed", "med"]);
    if (h.env === "internal" && h.ips) f.push(["Internal or admin, public DNS", "med"]);
    if (/cobrowse|zendesk|teamtailor|webflow|github\.io/.test(h.cname_chain)) f.push(["Vendor hosted", "mute"]);
    return f;
  }

  // ---------------- render ----------------
  function show(res) {
    R = res; A = ASM.analyze(res);
    const b = $("#banner");
    if (res.meta.mode === "snapshot") {
      b.innerHTML = `<div><b>Snapshot of 29 October 2026</b>: the exact collection behind the submitted Task A report. Press <b>Run passive scan</b> to collect the same data live from public sources now.</div>`;
    } else {
      b.innerHTML = `<div><b>Live scan</b> of ${E(res.meta.domain)} at ${E(new Date(res.meta.collected).toLocaleString())}. CT source: ${E(res.meta.ctSource)}.${res.meta.webNote ? " " + E(res.meta.webNote) + "." : ""}</div>`;
    }
    b.hidden = false;
    $("#report").innerHTML = [summary(), domains(), vendors(), email(), edge(), risks(), limits(), appendix(), exporter()].join("");
    // CSP forbids inline style attributes, so chart geometry is applied through the CSSOM
    document.querySelectorAll("[data-c]").forEach((el) => { el.style.background = el.dataset.c; if (el.dataset.w) el.style.width = el.dataset.w + "%"; });
    bindAppendix(); bindExport(); spy();
  }

  function summary() {
    const cdn = A.live.filter((h) => /CloudFront|Cloudflare|Fastly|Akamai|Imperva/.test(h.ingress)).length;
    const pd = (R.email[A.D] || { dmarc: [] }).dmarc[0] || "";
    const p = (/p=(\w+)/.exec(pd) || [])[1] || "none";
    const top = A.risks.map((r) => /^[A-Z][a-z]/.test(r.title) ? r.title[0].toLowerCase() + r.title.slice(1) : r.title);
    const thesis = A.goods.length
      ? `${E(A.D)} is well run where a central policy applies: ${E(A.goods.slice(0, 3).join("; "))}. The weaknesses sit wherever that policy does not reach: ${E(top.slice(0, 3).join("; "))}.`
      : `The main weaknesses: ${E(top.slice(0, 3).join("; "))}.`;
    const live = R.meta.mode === "live";
    return `<section class="sec" id="summary"><p class="eyebrow">1</p><h2>Summary and method</h2>
      <p class="thesis">${thesis}</p>
      <div class="tiles">
        <div class="tile"><div class="k">Names in CT</div><div class="v">${A.hosts.length}</div><div class="s">${R.scope.ctRoots.length} CT roots</div></div>
        <div class="tile"><div class="k">Resolve today</div><div class="v">${A.live.length}</div><div class="s">${A.hosts.length - A.live.length} stale or TXT only</div></div>
        <div class="tile ${pct(A.nonprod.length, A.live.length) > 30 ? "bad" : "warn"}"><div class="k">Non prod or internal</div><div class="v">${A.nonprod.length}</div><div class="s">${pct(A.nonprod.length, A.live.length)}% of live names</div></div>
        <div class="tile"><div class="k">Behind a CDN</div><div class="v">${pct(cdn, A.live.length)}%</div><div class="s">${cdn} of ${A.live.length} live names</div></div>
        <div class="tile ${p === "reject" ? "good" : "bad"}"><div class="k">Primary DMARC</div><div class="v">p=${E(p)}</div><div class="s">${Object.keys(R.email).filter((d) => !R.email[d].dmarc.length).length} domains without DMARC</div></div>
        <div class="tile ${A.dataEps.length ? "bad" : "good"}"><div class="k">Public data stores</div><div class="v">${A.dataEps.length}</div><div class="s">inferred from DNS only</div></div>
      </div>
      <p><b>Method.</b> Certificate transparency (crt.sh, Cert Spotter fallback), DNS record queries over public DNS over HTTPS, ${R.scope.brand.some((d) => d.endsWith(".hk")) ? "HKIRC WHOIS and " : ""}RDAP, Team Cymru ASN data, Amazon's published ip-ranges.json and the hstspreload.org API. Every hostname came from CT ${R.scope.preset ? "or passive DNS " : ""}and was resolved, never guessed. HTTP was limited to one GET, no redirects followed, to public production pages (apex, <code>www</code>, <code>app</code>, <code>api</code>) and <code>security.txt</code>. No dev, staging, admin, VPN or internal host received any request; no TLS or port probing. Email SANs and WHOIS contacts are discarded at collection, so no personal data is kept.${live ? "" : " This view is the 29 October collection that the report cites."}</p>
    </section>`;
  }

  function domains() {
    const rows = A.domains.map((d) => `<tr><td class="host">${E(d.domain)}${d.created ? ` <span class="count">(${E(d.created)})</span>` : ""}</td><td>${E(d.evidence)}</td><td>${chip(d.confidence, conf[d.confidence])}</td></tr>`).join("");
    const groups = A.groups.map((g) => `<div class="group"><b>${E(g.label)}</b> ${chip(g.names.length)}<div>${g.names.slice(0, 8).map((n) => E(short(n))).join(", ")}${g.names.length > 8 ? ", …" : ""}</div></div>`).join("");
    const sib = Object.entries(R.ct_siblings || {}).filter(([d]) => !R.scope.brand.includes(d) && !R.scope.related.includes(d)).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const look = (R.lookalikes || []).map((l) => `<tr><td class="host">${E(l.domain)}</td><td>${E(l.registrar || l.note || "")}</td><td class="num">${E(l.created || "")}</td><td>${l.created ? (l.post_brand ? chip("Postdates brand", "warn") : chip("Predates brand", "mute")) : chip("Unknown", "mute")}</td></tr>`).join("");
    return `<section class="sec" id="domains"><p class="eyebrow">2</p><h2>Domains and subdomains</h2>
      <p class="lede">Attribution uses registrant, registrar, homepage links, shared certificates and shared DNS. Shared CDN IPs and shared DNS hosting alone are never treated as proof, because unrelated customers share them.</p>
      <div class="tw"><table><thead><tr><th>Domain</th><th>How attributed</th><th>Confidence</th></tr></thead><tbody>${rows}</tbody></table></div>
      <h3>Subdomains</h3>
      <p>CT yields <b>${A.hosts.length}</b> names under ${R.scope.ctRoots.map(E).join(", ")}${R.meta.mode === "snapshot" ? "; passive DNS aggregators list more (about 386 in total, not reproduced here)" : ""}. <b>${A.live.length}</b> resolve today. A CT entry proves a certificate was issued, not that a service is live, so the inventory records status per name. <b>${A.nonprod.length} of ${A.live.length} live names are non production, internal, admin or remote access.</b></p>
      <div class="groups">${groups}</div>
      ${sib.length ? `<h3>Shared certificate candidates</h3><p class="count">Registrable domains that appear on the same certificates. Not attributed until a second signal agrees.</p><div class="chips">${sib.map(([d, n]) => chip(`${d} ×${n}`, "mute")).join("")}</div>` : ""}
      <h3>Lookalikes</h3>
      <p class="count">Graded by registration date against the brand${R.scope.founded ? ` (${E(R.scope.founded)})` : ""}. Registration data only; none was fetched.</p>
      ${look ? `<div class="tw"><table><thead><tr><th>Domain</th><th>Registrar</th><th>Created</th><th>Grade</th></tr></thead><tbody>${look}</tbody></table></div>` : `<p>No registered lookalikes found among the candidates checked.</p>`}
    </section>`;
  }

  function vendors() {
    const rows = A.vendors.map((v) => `<tr><td><b>${E(v.vendor)}</b></td><td>${E(v.evidence)}</td><td>${chip(v.strength, strength[v.strength])}</td></tr>`).join("");
    const notes = [];
    if (A.zendeskDouble) notes.push("<b>Zendesk</b> is a customer channel, an SPF authorised sender and a DKIM signer for the primary domain at once, so one tenant compromise gives both support takeover and DMARC passing mail as the company.");
    if (A.vendors.some((v) => v.vendor === "Cobrowse.io")) notes.push("<b>Cobrowse.io</b> lets support view a customer's live browser session, which should be covered in the privacy notice under the PDPO.");
    if (A.accountIds.length) notes.push(`An AWS account ID is disclosed in a public CNAME (${A.accountIds.map(E).join(", ")}).`);
    return `<section class="sec" id="vendors"><p class="eyebrow">3</p><h2>Third party SaaS and vendors</h2>
      <p class="lede">Strength: <b>Infrastructure</b> means DNS or mail routing depends on it; <b>Live page</b> means the homepage loads or allows it; <b>Attested</b> means a verification token only, which can be stale.</p>
      <div class="tw"><table><thead><tr><th>Vendor</th><th>Evidence</th><th>Strength</th></tr></thead><tbody>${rows}</tbody></table></div>
      ${notes.length ? `<div class="callout">${notes.join(" ")}</div>` : ""}
    </section>`;
  }

  function email() {
    const st = (v) => v === "Yes" ? chip("Yes", "good") : v === "No" ? chip("No", "mute") : E(v);
    const rows = A.emailRows.map((r) => `<tr><td class="host">${E(r.domain)}</td><td>${E(r.mx)}</td><td class="mono">${E(r.spf)}</td><td>${chip(r.dmarc, r.dmarcState === "good" ? "good" : r.dmarcState === "warn" ? "warn" : "bad")}</td><td class="mono">${E(r.dkim)}</td><td>${st(r.mtasts)}</td><td>${st(r.tlsrpt)}</td><td>${st(r.dnssec)}</td><td>${st(r.caa)}</td><td>${E(r.bimi)}</td></tr>`).join("");
    const ov = Object.entries(R.dmarc_overrides).map(([n, v]) => `<tr><td class="host">${E(n)}</td><td>${chip("p=" + ((/p=(\w+)/.exec(v) || [])[1] || "?"), /p=none/.test(v) ? "bad" : "good")}</td><td class="mono">${E(v.replace(/mailto:[^;,\s]+/g, "mailto:…"))}</td></tr>`).join("");
    return `<section class="sec" id="email"><p class="eyebrow">4</p><h2>Email authentication posture</h2>
      <p class="lede">DKIM is checked only for selectors that known vendors publish, so "none found" is not proof of absence.</p>
      <div class="tw"><table><thead><tr><th>Domain</th><th>MX</th><th>SPF</th><th>DMARC</th><th>DKIM</th><th>MTA-STS</th><th>TLS-RPT</th><th>DNSSEC</th><th>CAA</th><th>BIMI</th></tr></thead><tbody>${rows}</tbody></table></div>
      ${ov ? `<h3>Subdomain DMARC overrides</h3><p class="count">A subdomain's own DMARC record beats the parent's <code>sp=</code> tag.</p><div class="tw"><table><thead><tr><th>Name</th><th>Policy</th><th>Record (report addresses masked)</th></tr></thead><tbody>${ov}</tbody></table></div>` : ""}
      <h3>What an attacker can do</h3>
      <ol class="paths">${A.attackerPaths.map((p) => `<li>${p}</li>`).join("")}</ol>
      <div class="callout">${E(A.payoff)}</div>
    </section>`;
  }

  const COLORS = { CloudFront: "#2443c9", "AWS direct (ELB/EC2/API GW)": "#c9661a", Cloudflare: "#e3a008", Fastly: "#b4261a", "Global Accelerator": "#6a7fe0", Google: "#23784a" };
  function edge() {
    const entries = Object.entries(A.byIngress).sort((a, b) => b[1] - a[1]);
    const total = entries.reduce((s, [, n]) => s + n, 0);
    const extra = ["#7d5ba6", "#3f8f8f", "#8a8f99", "#a05a7a"]; let xi = 0;
    const col = (k) => COLORS[k] || extra[xi++ % extra.length];
    const cols = entries.map(([k]) => col(k));
    const bar = entries.map(([k, n], i) => `<span data-w="${(100 * n) / total}" data-c="${cols[i]}" title="${E(k)}: ${n}"></span>`).join("");
    const legend = entries.map(([k, n], i) => `<span><i data-c="${cols[i]}"></i>${E(k)} <b>${n}</b></span>`).join("");
    const items = [];
    if (A.dataEps.length) items.push(["Data stores", "bad", `${A.dataEps.map((h) => `<code>${E(short(h.name))}</code> → ${E(resolvesTo(h))}`).join("; ")}. Reachability is not tested.`]);
    if (A.bypass.length) items.push(["CDN bypass", "warn", `${A.bypass.slice(0, 8).map((h) => `<code>${E(short(h.name))}</code>`).join(", ")}${A.bypass.length > 8 ? ` and ${A.bypass.length - 8} more` : ""} resolve straight to AWS load balancers, EC2 or API Gateway while the main hosts sit behind a CDN.`]);
    A.headerIssues.forEach((i) => items.push(["Headers", "med", `<code>${E(short(i.host))}</code> ${i.text}.`]));
    if (A.apexNoHsts) items.push(["HSTS", "med", `The apex returns ${E((R.web.find((w) => w.url === `https://${A.D}/`) || {}).status || "a redirect")} with no HSTS header, so a <code>preload</code> token on <code>www</code> is never honoured; hstspreload.org lists the domain as <b>${E((R.hsts_preload || {})[A.D] || "unknown")}</b>.`]);
    A.lame.forEach((h) => items.push(["DNS", "bad", `<code>${E(h.name)}</code> is delegated to nameservers that refuse the zone: a lame delegation and subdomain hijack candidate.`]));
    items.push(["DNS", A.dangling.length ? "bad" : "good", A.dangling.length ? `Dangling CNAMEs: ${A.dangling.map((h) => `<code>${E(h.name)}</code>`).join(", ")}.` : "No dangling CNAMEs found; all targets resolve."]);
    if (A.sectxtMissing && A.sectxtMissing.length) items.push(["security.txt", "med", A.sectxtMissing[0] === "file" ? "No security.txt found." : `security.txt lacks ${A.sectxtMissing.map((f) => `<code>${f}</code>`).join(" and ")}.`]);
    if (R.meta.webNote) items.push(["Headers", "mute", E(R.meta.webNote) + "."]);
    const webRows = R.web.map((w) => `<tr><td class="host">${E(w.url.replace("https://", ""))}</td><td class="num">${E(w.status || w.error || "")}</td><td>${E(w.edge || "")}</td><td>${chip(w.csp_mode || "n/a", w.csp_mode === "enforced" ? (w.csp_script_src_permissive ? "warn" : "good") : w.csp_mode === "report-only" ? "warn" : "mute")}</td><td>${(w.security_headers || {})["strict-transport-security"] ? chip("HSTS", "good") : chip("no HSTS", "mute")}</td><td class="mono">${E(Object.entries(w.disclosure_headers || {}).map(([k, v]) => `${k}: ${v}`).join("; "))}</td></tr>`).join("");
    return `<section class="sec" id="edge"><p class="eyebrow">5</p><h2>Edge protections and inconsistencies</h2>
      <p class="lede">Where each of the ${total} live names terminates, from CNAME chains, AWS published ranges and ASN data.</p>
      <div class="stack" role="img" aria-label="Ingress mix">${bar}</div><div class="legend">${legend}</div>
      <ul class="find">${items.map(([k, s, t]) => `<li>${chip(k, s)}<span>${t}</span></li>`).join("")}</ul>
      ${webRows ? `<h3>Production pages fetched (one GET each, no redirects)</h3><div class="tw"><table><thead><tr><th>URL</th><th>Status</th><th>Edge</th><th>CSP</th><th>HSTS</th><th>Disclosure headers</th></tr></thead><tbody>${webRows}</tbody></table></div>` : ""}
      ${A.goods.length ? `<h3>Good, leave as is</h3><div class="chips">${A.goods.map((g) => chip(g, "good")).join("")}</div>` : ""}
    </section>`;
  }

  function risks() {
    const cards = A.risks.map((r, i) => { const [label, cls, c] = sev(r.score);
      return `<article class="risk s-${cls}"><div class="rank">${i + 1}</div><div class="body">
        <h3>${E(r.title)} ${chip(label, c)}</h3><p>${r.detail}</p>
        <div class="fix"><div><span class="lbl">Remediation I would propose</span>${r.fix}</div><div><span class="lbl">Effort and cost (HK$)</span><span class="cost">${E(r.cost)}</span></div></div>
      </div></article>`; }).join("");
    const once = A.risks.reduce((s, r) => s + Number((/~HK\$(\d+)k/.exec(r.cost) || [])[1] || 0), 0);
    const t = A.risks.map((r) => r.title);
    const lo = (t.some((x) => /Email|spoofed/.test(x)) ? 20 : 0) + (t.some((x) => /bypass/.test(x)) ? 12 : 0) + (t.some((x) => /estate/.test(x)) ? 3 : 0);
    const hi = (t.some((x) => /Email|spoofed/.test(x)) ? 40 : 0) + (t.some((x) => /bypass/.test(x)) ? 12 : 0) + (t.some((x) => /estate/.test(x)) ? 8 : 0);
    return `<section class="sec" id="risks"><p class="eyebrow">6</p><h2>Top 5 risks</h2>
      <p class="lede">Ranked by attacker value against ease. Internal effort is costed at about HK$4,000 per engineer day.</p>
      <div class="risks">${cards || "<p>No significant risks found from passive data.</p>"}</div>
      ${cards ? `<p class="total">Year one total: about HK$${once}k internal effort${hi ? ` plus HK$${lo}k to ${hi}k recurring` : ""}.</p>` : ""}
    </section>`;
  }

  function limits() {
    return `<section class="sec" id="limits"><p class="eyebrow">7</p><h2>Not determinable passively, and what needs authorisation</h2>
      <div class="cols"><div><h3>Could not determine</h3><ul>${A.cannot.map((x) => `<li>${E(x)}</li>`).join("")}</ul></div>
      <div><h3>Needs written authorisation</h3><ul>${A.needAuth.map((x) => `<li>${E(x)}</li>`).join("")}</ul></div></div>
    </section>`;
  }

  function appendix() {
    const rows = A.notable.map((h) => `<tr><td class="host">${E(h.name)}</td><td>${E(resolvesTo(h))}</td><td>${E(h.ingress || "n/a")}</td><td><div class="chips">${findingsFor(h).map(([t, k]) => chip(t, k)).join("") || chip("No finding", "mute")}</div></td></tr>`).join("");
    return `<section class="sec" id="appendix"><p class="eyebrow">Appendix</p><h2>Host inventory</h2>
      <p class="lede">Notable live hosts first, then every name from CT with its resolution status.</p>
      <div class="tw"><table><thead><tr><th>Host</th><th>Resolves to</th><th>Edge</th><th>Finding</th></tr></thead><tbody>${rows}</tbody></table></div>
      <h3>All names</h3>
      <div class="filters" role="group" aria-label="Filter hosts">
        ${[["live", "Live"], ["findings", "With findings"], ["non-prod", "Non production"], ["internal", "Internal or admin"], ["dead", "Not resolving"], ["all", "All"]].map(([k, l]) => `<button type="button" data-f="${k}" aria-pressed="${k === filter}">${l}</button>`).join("")}
        <label for="q" class="sr">Search hosts</label><input id="q" placeholder="search name, CNAME, ASN" value="${E(query)}">
        <span class="count" id="inv-count"></span>
      </div>
      <div class="tw inv"><table><thead><tr><th>Name</th><th>Status</th><th>Env</th><th>Resolves to</th><th>Edge</th><th>ASN</th><th>CNAME chain</th></tr></thead><tbody id="inv"></tbody></table></div>
    </section>`;
  }
  function drawInventory() {
    const q = query.toLowerCase();
    const rows = A.hosts.filter((h) => filter === "all" || (filter === "live" && h.ips) || (filter === "dead" && !h.ips) ||
      (filter === "findings" && findingsFor(h).some(([, k]) => k === "bad" || k === "warn")) || (filter === h.env && h.ips))
      .filter((h) => !q || [h.name, h.cname_chain, h.asn, h.ingress].join(" ").toLowerCase().includes(q));
    $("#inv").innerHTML = rows.map((h) => `<tr><td class="host">${E(h.name)}</td><td>${chip(h.status, h.status === "NOERROR" ? "good" : h.status === "SERVFAIL" ? "bad" : "mute")}</td><td>${chip(h.env, h.env === "prod" ? "" : h.env === "non-prod" ? "med" : "warn")}</td><td>${E(resolvesTo(h))}</td><td>${E(h.ingress || "")}</td><td class="mono">${E(h.asn.split(" ")[0] || "")}</td><td class="mono">${E(h.cname_chain)}</td></tr>`).join("");
    $("#inv-count").textContent = `${rows.length} of ${A.hosts.length}`;
  }
  function bindAppendix() {
    document.querySelectorAll(".filters button").forEach((b) => b.addEventListener("click", () => {
      filter = b.dataset.f; document.querySelectorAll(".filters button").forEach((x) => x.setAttribute("aria-pressed", String(x === b))); drawInventory();
    }));
    $("#q").addEventListener("input", (e) => { query = e.target.value; drawInventory(); });
    drawInventory();
  }

  // ---------------- export ----------------
  function exporter() {
    return `<section class="sec" id="export"><p class="eyebrow">Export</p><h2>Export and collection script</h2>
      <p class="lede">The same files the Task A submission ships: the host inventory, the posture data and the report text. The collection logic is also published as a standalone Python script.</p>
      <div class="exports">
        <button class="btn" type="button" data-x="csv">hosts.csv</button>
        <button class="btn" type="button" data-x="json">posture.json</button>
        <button class="btn" type="button" data-x="md">report.md</button>
        <a class="btn" href="recon.py" download>recon.py</a>
      </div>
      <p class="count">Run the script with <code>python3 -I recon.py out/</code> (Python 3.9+, standard library and the <code>whois</code> command). Same rules of engagement as this console.</p>
    </section>`;
  }
  function save(name, text, type) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }
  function csv() {
    const cols = ["name", "status", "cname_chain", "ips", "asn", "aws_service", "ingress", "public_data_endpoint", "dangling_cname", "lame_delegation", "own_dmarc"];
    const q = (v) => { v = String(v ?? ""); return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v; };
    return [cols.join(","), ...R.hosts.map((h) => cols.map((c) => q(typeof h[c] === "boolean" ? (h[c] ? "True" : "False") : h[c])).join(","))].join("\n") + "\n";
  }
  function md() {
    const L = [];
    L.push(`# External attack surface: ${A.D}`, "", `Passive reconnaissance only. Collected ${R.meta.collected.slice(0, 10)}.`, "", "## 1. Summary and method", "", strip($("#summary .thesis").innerHTML), "");
    L.push("## 2. Domains and subdomains", "", "| Domain | How attributed | Confidence |", "|---|---|---|", ...A.domains.map((d) => `| ${d.domain} | ${d.evidence} | ${d.confidence} |`), "");
    L.push(`CT yields ${A.hosts.length} names; ${A.live.length} resolve; ${A.nonprod.length} of ${A.live.length} live names are non production, internal, admin or remote access.`, "");
    L.push("## 3. Third party SaaS and vendors", "", "| Vendor | Evidence | Strength |", "|---|---|---|", ...A.vendors.map((v) => `| ${v.vendor} | ${v.evidence} | ${v.strength} |`), "");
    L.push("## 4. Email authentication posture", "", "| Domain | MX | SPF | DMARC | MTA-STS | DNSSEC | CAA |", "|---|---|---|---|---|---|---|", ...A.emailRows.map((r) => `| ${r.domain} | ${r.mx} | ${r.spf} | ${r.dmarc} | ${r.mtasts} | ${r.dnssec} | ${r.caa} |`), "");
    A.attackerPaths.forEach((p, i) => L.push(`${i + 1}. ${strip(p)}`)); L.push("", A.payoff, "");
    L.push("## 5. Edge protections and inconsistencies", "", Object.entries(A.byIngress).map(([k, n]) => `${k} ${n}`).join(", ") + ".", "");
    document.querySelectorAll("#edge .find li").forEach((li) => L.push(`* ${strip(li.innerHTML).replace(/\s+/g, " ").trim()}`)); L.push("");
    L.push("## 6. Top 5 risks", "", "| # | Risk | Remediation | Effort and cost (HK$) |", "|-|---|---|---|", ...A.risks.map((r, i) => `| ${i + 1} | **${r.title}.** ${strip(r.detail)} | ${strip(r.fix)} | ${r.cost} |`), "");
    L.push("## 7. Not determinable passively, and what needs authorisation", "", "**Could not determine:** " + A.cannot.join("; ") + ".", "", "**Needs written authorisation:** " + A.needAuth.join("; ") + ".", "");
    L.push("## Appendix: notable hosts", "", "| Host | Resolves to | Edge | Finding |", "|---|---|---|---|", ...A.notable.map((h) => `| ${h.name} | ${resolvesTo(h)} | ${h.ingress || "n/a"} | ${findingsFor(h).map(([t]) => t).join("; ")} |`), "");
    return L.join("\n").replace(/—|–/g, ",");
  }
  function bindExport() {
    document.querySelectorAll("[data-x]").forEach((b) => b.addEventListener("click", () => {
      const k = b.dataset.x, base = A.D.replace(/\./g, "_");
      if (k === "csv") save(`${base}_hosts.csv`, csv(), "text/csv");
      if (k === "json") { const { hosts, ...rest } = R; save(`${base}_posture.json`, JSON.stringify(rest, null, 2), "application/json"); }
      if (k === "md") save(`${base}_report.md`, md(), "text/markdown");
    }));
  }

  // ---------------- section index highlight ----------------
  function spy() {
    const links = [...document.querySelectorAll(".toc a")];
    const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) links.forEach((a) => a.classList.toggle("on", a.getAttribute("href") === "#" + e.target.id)); }), { rootMargin: "-40% 0px -55% 0px" });
    document.querySelectorAll(".sec").forEach((s) => io.observe(s));
  }

  function start() {
    $("#snap").hidden = true;
    $("#report").innerHTML = `<section class="sec" id="summary"><p class="eyebrow">Start</p><h2>Passive attack surface, written up</h2>
      <p class="thesis">Enter a domain and press <b>Run passive scan</b>. In about a minute you get the Task A report: domains and how each was attributed, third party vendors with evidence, email authentication posture and what an attacker could do with the gaps, edge coverage, the top 5 risks with remediation and HK$ cost, what passive data cannot tell you, and a host appendix.</p>
      <p><b>Sources:</b> certificate transparency, DNS over HTTPS, Team Cymru ASN, AWS published ranges and RDAP${API ? ", plus one GET to the apex, <code>www</code>, <code>app</code>, <code>api</code> and <code>security.txt</code>" : ""}. Nothing is port scanned, brute forced or logged into, and no non production host receives a request.</p>
      ${API ? "" : `<p class="count">This copy runs on a static host, so HTTP header checks are skipped. Run <code>node server.mjs</code> from the repository to include them.</p>`}
      <div class="exports"><button class="btn primary" type="button" id="try">Scan bowtie.com.hk</button></div></section>`;
    $("#try").addEventListener("click", () => { $("#domain").value = "bowtie.com.hk"; $("#scan").requestSubmit(); });
    log("Ready. Enter a domain and press Run passive scan.", "ok"); state("Ready", "");
  }
  // Open on the 29 Oct collection when snapshot.js ships with this copy; otherwise on the start screen.
  const sn = document.createElement("script");
  sn.src = "snapshot.js";
  sn.onload = () => {
    if (!window.SNAPSHOT) return start();
    log("Ready. Showing the 29 Oct 2026 collection. Enter a domain and press Run passive scan for a live collection.", "ok");
    show(window.SNAPSHOT); state("Snapshot: 29 Oct 2026", "ok");
  };
  sn.onerror = start;
  document.body.appendChild(sn);
})();
