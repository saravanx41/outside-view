#!/usr/bin/env python3
"""Passive external attack surface collection for Bowtie (take-home, Task A).

Every claim in the report can be reproduced by this script. Sources, all passive:
  * crt.sh certificate transparency (names are taken from CT, never guessed)
  * DNS record queries over public DNS-over-HTTPS (Cloudflare, fallback Google)
  * Team Cymru IP to ASN, and Amazon's published ip-ranges.json (IP to AWS service)
  * HKIRC WHOIS (.hk) and RDAP (gTLDs); output filtered to company, registrar, dates
  * hstspreload.org status API
  * One GET, no redirect following, to each host in HTTP_ALLOWLIST (public production
    pages only). No other host receives any HTTP request.

Deliberately NOT done: port scans, TLS version probing, wordlists, brute force, logins,
HTTP to any dev/staging/admin/internal host. DKIM checks query only selectors that a
vendor publicly documents. No personal data is stored: email SANs are dropped and WHOIS
contact fields are discarded.

Usage:  python3 -I recon.py out/
"""
import csv, ipaddress, json, pathlib, re, subprocess, sys, time
import urllib.error, urllib.parse, urllib.request

BRAND = ["bowtie.com.hk", "bowtie.hk", "virtualinsurer.hk", "virtualinsurer.com.hk"]
CT_ROOTS = ["bowtie.com.hk", "bowtie.hk", "virtualinsurer.hk"]
# Names seen in passive DNS but absent from CT; resolved like any other, never fetched.
EXTRA_NAMES = ["marketing.bowtie.com.hk"]
RELATED = ["bowtiego.com", "gobowtie.com", "bowtiejphealth.com"]  # DNS only
BRAND_FOUNDED = "2017-11"  # earliest brand registration (bowtie.com.hk, HKIRC)
# Lookalike candidates: manual typo/lure permutations, looked up in RDAP only, never fetched.
LOOKALIKES = ["bowtielife.com", "bowtiemedical.com", "bowite.com", "powtie.com",
              "bowtieinsurance.com", "bowtiecare.com", "bowtiepay.com",
              "bowtiegroup.net", "bowtiehk.com"]
HTTP_ALLOWLIST = ["https://www.bowtie.com.hk/", "https://bowtie.com.hk/",
                  "https://app.bowtie.com.hk/", "https://api.bowtie.com.hk/",
                  "https://www.bowtie.com.hk/.well-known/security.txt"]
DKIM_SELECTORS = {"google": "Google Workspace", "selector1": "Microsoft 365",
                  "selector2": "Microsoft 365", "k1": "Mailchimp", "s1": "SendGrid",
                  "zendesk1": "Zendesk", "zendesk2": "Zendesk", "hs1": "HubSpot"}
DISCLOSURE_HEADERS = ["server", "x-powered-by", "api-release", "api-commit-hash"]
SEC_HEADERS = ["strict-transport-security", "content-security-policy",
               "content-security-policy-report-only", "x-frame-options",
               "x-content-type-options", "referrer-policy", "permissions-policy"]
UA = {"User-Agent": "passive-asm-takehome/2.0"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def get(url, accept=None, timeout=20, follow=True):
    h = dict(UA, **({"accept": accept} if accept else {}))
    req = urllib.request.Request(url, headers=h)
    op = urllib.request.urlopen if follow else OPENER.open
    try:
        with op(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:  # 3xx (when not following) and 4xx/5xx
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def doh(name, rtype, base="https://cloudflare-dns.com/dns-query"):
    """Return (rcode, [(type, data)], ad_flag, comment)."""
    for b in (base, "https://dns.google/resolve"):
        try:
            _, _, body = get(f"{b}?name={urllib.parse.quote(name)}&type={rtype}",
                             accept="application/dns-json")
            j = json.loads(body)
            return (j.get("Status"), [(a["type"], a["data"]) for a in j.get("Answer", [])],
                    j.get("AD"), j.get("Comment", ""))
        except Exception:
            continue
    return None, [], None, ""


def txt(name):
    return [d.replace('" "', "").strip('"') for _, d in doh(name, "TXT")[1]]


# ---------- discovery ----------
def ct_names(root, cache_dir=pathlib.Path("raw")):
    cache, body = cache_dir / f"crt_{root}.json", None
    for attempt in range(3):  # crt.sh often returns 502 under load
        try:
            _, _, body = get(f"https://crt.sh/?q=%25.{root}&output=json", timeout=120)
            json.loads(body)
            cache_dir.mkdir(exist_ok=True); cache.write_bytes(body)
            break
        except Exception:
            body = None; time.sleep(10 * (attempt + 1))
    if body is None:
        if not cache.exists():
            sys.exit(f"crt.sh unavailable for {root} and no cached raw/{cache.name}; retry later")
        print(f"crt.sh unavailable for {root}; using cached {cache}", file=sys.stderr)
        body = cache.read_bytes()  # fall back to the last successful pull
    names = set()
    for row in json.loads(body):
        for n in row["name_value"].lower().split("\n"):
            n = n.lstrip("*.").strip()
            if n.endswith(root) and "@" not in n:  # drop email SANs (PDPO)
                names.add(n)
    return names


# ---------- resolution and hosting ----------
def load_aws_ranges(cache=pathlib.Path("raw/aws-ip-ranges.json")):
    try:
        _, _, body = get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=30)
        cache.parent.mkdir(exist_ok=True); cache.write_bytes(body)
    except Exception:
        body = cache.read_bytes()
    nets = []
    for p in json.loads(body)["prefixes"]:
        nets.append((ipaddress.ip_network(p["ip_prefix"]), p["service"], p["region"]))
    return nets


def aws_service(ip, nets):
    a = ipaddress.ip_address(ip)
    hits = [(n.prefixlen, s, r) for n, s, r in nets if a in n and s != "AMAZON"]
    if not hits:
        return "private" if a.is_private else ""
    _, s, r = max(hits)
    return f"{s}@{r}"


def asn(ip, cache):
    if ip not in cache:
        rev = ".".join(reversed(ip.split(".")))
        t = txt(f"{rev}.origin.asn.cymru.com")
        num = t[0].split("|")[0].strip().split()[0] if t else ""
        d = txt(f"AS{num}.asn.cymru.com") if num else []
        cache[ip] = f"AS{num} {d[0].split('|')[-1].strip()}" if d else ""
    return cache[ip]


def resolve(name, nets, asn_cache):
    rc, ans, _, comment = doh(name, "A")
    cnames = [d.rstrip(".") for t, d in ans if t == 5]
    ips = [d for t, d in ans if t == 1]
    status = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN"}.get(rc, str(rc))
    if rc == 0 and not ans:
        status = "NODATA"
    lame = False
    if rc == 2:  # SERVFAIL: check for a lame delegation (dangling NS)
        _, _, _, c = doh(name, "NS", base="https://dns.google/resolve")
        lame = "lame delegation" in (c or comment).lower()
    svc = aws_service(ips[0], nets) if ips else ""
    ingress = ("CloudFront" if "CLOUDFRONT" in svc else "Global Accelerator" if "GLOBALACC" in svc
               else "AWS direct (ELB/EC2/API GW)" if svc.startswith("EC2") else "")
    owner = asn(ips[0], asn_cache) if ips else ""
    if not ingress and ips:
        ingress = owner.split(" ", 1)[-1][:40]
    # Any name that exists may carry its own _dmarc (a TXT-only sending name has no A record).
    dmarc = [t for t in txt(f"_dmarc.{name}") if t.startswith("v=DMARC1")] if rc != 3 else []
    return {"name": name, "status": status, "cname_chain": " > ".join(cnames),
            "ips": " ".join(ips), "asn": owner, "aws_service": svc, "ingress": ingress,
            "public_data_endpoint": any(k in " ".join(cnames) for k in
                                        ("redshift", "rds.", "aurora", "opensearch", "es.amazonaws")),
            "dangling_cname": bool(cnames) and not ips, "lame_delegation": lame,
            "own_dmarc": dmarc[0] if dmarc else ""}


# ---------- email and DNS posture ----------
def spf_lookups(domain, seen=None):
    seen = seen if seen is not None else set()
    if domain in seen:
        return 0
    seen.add(domain)
    n = 0
    for rec in [t for t in txt(domain) if t.startswith("v=spf1")]:
        for term in rec.split()[1:]:
            t = term.lstrip("+-~?")
            if t.startswith(("include:", "redirect=")):
                n += 1 + spf_lookups(re.split("[:=]", t, maxsplit=1)[1], seen)
            elif t.split(":")[0] in ("a", "mx", "ptr") or t.startswith("exists:"):
                n += 1
    return n


def email_posture(d):
    out = {"mx": [x for _, x in doh(d, "MX")[1]],
           "spf": [t for t in txt(d) if t.startswith("v=spf1")],
           "dmarc": [t for t in txt(f"_dmarc.{d}") if t.startswith("v=DMARC1")],
           "mta_sts": txt(f"_mta-sts.{d}"), "tls_rpt": txt(f"_smtp._tls.{d}"),
           "bimi": txt(f"default._bimi.{d}"), "caa": [x for _, x in doh(d, "CAA")[1]],
           "ds": [x for _, x in doh(d, "DS")[1]], "spf_lookups": spf_lookups(d),
           "dkim": {s: v for s, v in DKIM_SELECTORS.items() if txt(f"{s}._domainkey.{d}")},
           "verification_txt": sorted({t.split("=")[0] for t in txt(d)
                                       if "verif" in t.lower() or t.startswith(("MS=", "mgverify"))})}
    out["bimi_has_vmc"] = any("a=" in b for b in out["bimi"])
    return out


def registration(d):
    if d.endswith(".hk"):
        w = ""
        for attempt in range(3):  # HKIRC throttles back-to-back queries
            try:
                w = subprocess.run(["whois", "-h", "whois.hkirc.hk", d], capture_output=True,
                                   text=True, timeout=30).stdout
            except Exception:
                pass
            if "Company English Name" in w:
                break
            time.sleep(15)
        grab = lambda k: (re.search(rf"{k}[^:]*:\s*(.+)", w) or [None, ""])[1].strip()
        return {"registrant_company": grab("Company English Name"),
                "registrar": grab("Registrar Name"), "created": grab("Commencement Date"),
                "expires": grab("Expiry Date")}  # contact fields deliberately discarded
    try:
        _, _, body = get(f"https://rdap.org/domain/{d}", timeout=30)
        j = json.loads(body)
    except Exception:
        return {}
    ev = {e["eventAction"]: e["eventDate"][:10] for e in j.get("events", [])}
    reg = [v[3] for e in j.get("entities", []) if "registrar" in e.get("roles", [])
           for v in e.get("vcardArray", [None, []])[1] if v[0] == "fn"]
    return {"registrar": reg[0] if reg else "", "created": ev.get("registration", ""),
            "expires": ev.get("expiration", "")}


# ---------- public production pages (allowlist only) ----------
def web(url):
    try:
        st, h, body = get(url, follow=False)
    except Exception as e:
        return {"url": url, "error": str(e)}
    res = {"url": url, "status": st, "location": h.get("location", ""),
           "security_headers": {k: h[k] for k in SEC_HEADERS if k in h},
           "disclosure_headers": {k: ("<present, value withheld>" if "hash" in k else h[k])
                                  for k in DISCLOSURE_HEADERS if k in h},
           "edge": "CloudFront" if "cloudfront" in h.get("via", "").lower()
                   else "Cloudflare" if "cf-ray" in h else h.get("server", "")}
    csp = h.get("content-security-policy", "")
    res["csp_mode"] = ("enforced" if csp else "report-only"
                       if "content-security-policy-report-only" in h else "none")
    res["csp_script_src_permissive"] = bool(re.search(r"script-src[^;]*'unsafe-inline'[^;]*https:", csp))
    if url.rstrip("/").endswith("www.bowtie.com.hk") and body:
        html = body.decode("utf-8", "replace")
        tags = re.findall(r"<script[^>]+src=\"(https?://[^\"]+)\"[^>]*>", html)
        res["external_scripts_without_sri"] = [
            s.split("?")[0] for s in tags
            if not re.search(r"<script[^>]+src=\"" + re.escape(s) + r"\"[^>]*integrity=", html)]
        res["third_party_hosts"] = sorted(set(re.findall(r"https?://([a-z0-9.-]+)", html)) -
                                          {"www.bowtie.com.hk"})
    if url.endswith("security.txt") and body:
        t = body.decode("utf-8", "replace")
        res["securitytxt_fields"] = sorted(set(re.findall(r"^([A-Za-z-]+):", t, re.M)))
    return res


def main(outdir):
    out = pathlib.Path(outdir); out.mkdir(parents=True, exist_ok=True)
    names = set(BRAND) | set(EXTRA_NAMES)
    for r in CT_ROOTS:
        names |= ct_names(r)
    nets, asn_cache = load_aws_ranges(), {}
    rows = []
    for n in sorted(names):
        rows.append(resolve(n, nets, asn_cache)); time.sleep(0.05)
    with open(out / "hosts.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)

    posture = {
        "registration": {d: registration(d) for d in BRAND + RELATED},
        "email": {d: email_posture(d) for d in BRAND + RELATED},
        "dmarc_overrides": {r["name"]: r["own_dmarc"] for r in rows
                            if r["own_dmarc"] and r["name"] not in BRAND},
        "hsts_preload": {d: json.loads(get(f"https://hstspreload.org/api/v2/status?domain={d}")[2])
                         .get("status") for d in ("bowtie.com.hk", "bowtie.hk")},
        "web": [web(u) for u in HTTP_ALLOWLIST],
        "lookalikes": [dict(domain=d, **registration(d)) for d in LOOKALIKES],
    }
    for l in posture["lookalikes"]:
        l["post_brand"] = bool(l.get("created")) and l["created"][:7] >= BRAND_FOUNDED
    json.dump(posture, open(out / "posture.json", "w"), indent=2)

    live = [r for r in rows if r["ips"]]
    print(f"{len(rows)} names, {len(live)} resolve")
    print("ingress:", {k: sum(r['ingress'] == k for r in live) for k in {r['ingress'] for r in live}})
    print("public data endpoints:", [r["name"] for r in rows if r["public_data_endpoint"]])
    print("lame delegations:", [r["name"] for r in rows if r["lame_delegation"]])
    print("dangling CNAMEs:", [r["name"] for r in rows if r["dangling_cname"]])
    print("DMARC overrides:", {k: v.split(";")[1].strip() for k, v in posture["dmarc_overrides"].items()})
    print("no DMARC:", [d for d, e in posture["email"].items() if not e["dmarc"]])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "out")
