"""
Browser smoke test for the standalone UI pages (NOT a pytest module).

    python tests/ui_demo_server.py --db /tmp/ui.db --port 8766 &
    python tests/ui_smoke_pages.py http://127.0.0.1:8766 [--shots DIR] [--headed]

Opens /ui/upload, /ui/findings, /ui/topology, /ui/attestation and
/ui/fw-topology in Chromium (Playwright), drives the main interactions and
fails (exit 1) on any of:
  * console errors / uncaught page errors
  * unexpected 4xx/5xx responses
  * `window.__xss` defined or an `img[data-xss]` element in the DOM
    (ui_demo_server.py plants such payloads in untrusted fields)
  * findings.html counters that disagree with GET /findings/summary
  * horizontal page scroll at 400px width
Multi-site phase 3: log uploads send the optional "map unknown devices to"
site and show the routing summary (held / new mappings / conflicts).
Also covered: multi-vendor syslog upload (/ingest/syslog: vendor_hint, device
name fallback, per-vendor summary), level pickers from /purdue-levels,
findings last seen / occurrences and "Run reviews now", topology stale badge,
address history and the N-16 "Partial view: N of M" truncation notice.
Multi-site (phase 1): upload.html's required site picker (client-side
refusal, server 422 for an unknown site, inline "+ New site", `site` sent
only for non-log kinds), the site filter on findings / topology /
attestation / fw-topology (counts match the API's ?site_id= answers), and
attestation / FW-aware PCAP uploads naming their site.
Multi-site (phase 2): /ui/topology (the console's Host Topology, standalone) and fw-topology.html work on ONE site -
they run with Plant A pre-selected (the seed has overlapping data in Plant A
and Plant B); findings.html's "Run reviews now" runs the selected site only.
Always one site (owner 2026-10-13): no "All sites" option on any page; with
nothing remembered the default / first site is selected.
Full-page screenshots (desktop + 400px) go to --shots.

The upload step posts every sample in sample_data/ through the upload form,
so run it against a throwaway demo database - and against a FRESHLY SEEDED
one each time: several assertions (e.g. the current attestation's proof
link, a zone label appearing once) assume the seed state and fail on a DB
that this script or tests/ui_smoke_index.py has already modified.
"""
import argparse
import json
import re
import sys
import tempfile
import traceback
import urllib.parse
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright, Page, expect

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_data"
XSS = '<img src=x data-xss=1 onerror="window.__xss=(window.__xss||0)+1">'
TIMEOUT = 20_000


class Failure(Exception):
    pass


def get_json(base, path):
    with urllib.request.urlopen(base + path, timeout=30) as r:
        return json.loads(r.read())


class PageRun:
    """Collects console errors / bad responses for one page."""

    def __init__(self, browser, base, name, shots, allowed=(), site=None):
        self.base, self.name, self.shots = base, name, shots
        self.allowed = list(allowed)          # (method, url regex, status)
        self.errors: list[str] = []
        self.allowed_hits = 0
        self.ctx = browser.new_context(viewport={"width": 1400, "height": 900})
        if site is not None:
            # Pre-select a site once per tab (the console's shared localStorage
            # key); later changes / reloads keep whatever the page selected.
            self.ctx.add_init_script(
                "try { if (!sessionStorage.getItem('smoke_site')) { localStorage.setItem('iasc_site', '%s');"
                " sessionStorage.setItem('smoke_site', '1'); } } catch (e) {}" % int(site))
        self.page: Page = self.ctx.new_page()
        self.page.set_default_timeout(TIMEOUT)
        self.page.on("console", self._on_console)
        self.page.on("pageerror", lambda exc: self.errors.append(f"pageerror: {exc}"))
        self.page.on("response", self._on_response)
        self.page.on("dialog", lambda d: (self.errors.append(f"unexpected dialog: {d.message}"), d.dismiss()))

    def _on_console(self, msg):
        if msg.type != "error":
            return
        if "Failed to load resource" in msg.text and self.allowed_hits:
            return                           # the browser's log line for an expected 4xx
        self.errors.append(f"console.error: {msg.text}")

    def _on_response(self, resp):
        if resp.status < 400:
            return
        method = resp.request.method
        for m, pat, st in self.allowed:
            if m == method and st == resp.status and re.search(pat, resp.url):
                self.allowed_hits += 1
                return
        self.errors.append(f"HTTP {resp.status} {method} {resp.url}")

    def check_xss(self, where=""):
        xss = self.page.evaluate("() => window.__xss")
        imgs = self.page.locator("img[data-xss]").count()
        if xss is not None or imgs:
            self.errors.append(f"XSS fired {where}: window.__xss={xss!r}, img[data-xss]={imgs}")
        stray = self.page.evaluate("""() => {
            const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
            const bad = [];
            while (w.nextNode()) {
                const t = w.currentNode.textContent.trim();
                if (["null", "undefined", "[object Object]", "NaN"].includes(t)) bad.push(t);
            }
            return bad;
        }""")
        if stray:
            self.errors.append(f"stray rendered values {where}: {stray}")

    def check_no_hscroll(self):
        sw, cw = self.page.evaluate(
            "() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]")
        if sw > cw + 1:
            self.errors.append(f"horizontal page scroll at {cw}px: scrollWidth={sw}")

    def shot(self, suffix):
        path = Path(self.shots) / f"{self.name}_{suffix}.png"
        self.page.screenshot(path=str(path), full_page=True)

    def mobile(self, ready_selector):
        self.page.set_viewport_size({"width": 400, "height": 800})
        self.page.reload()
        self.page.wait_for_selector(ready_selector, state="attached")
        self.page.wait_for_timeout(400)
        self.check_no_hscroll()
        self.check_xss("(mobile)")
        self.shot("400px")

    def close(self):
        self.ctx.close()


# ------------------------------------------------------------------ upload --
UPLOADS = [
    # kind, file, {vendor, name, zone_from, zone_to, baseline}
    ("pcap", "multi_protocol_sample.pcap", {}),
    ("fortigate_config", "sample_fortigate_config.txt", {"name": "FW-SMOKE", "zf": "4", "zt": "3"}),
    ("firewall", "sample_firewall_cisco.txt", {"vendor": "cisco", "name": "CISCO-SMOKE", "zf": "3", "zt": "2"}),
    ("firewall", "sample_firewall_pfsense.xml", {"vendor": "pfsense", "name": "PF-SMOKE"}),
    ("firewall", "sample_firewall_panos.xml", {"vendor": "palo_alto", "name": "PA-SMOKE"}),
    ("firewall", "sample_firewall_panos_set.txt", {"vendor": "palo_alto"}),
    ("switch", "sample_switch_running_config.txt", {"vendor": "cisco", "name": "SW-SMOKE"}),
    ("switch", "sample_switch_hp_lldp_detail.txt", {"vendor": "hp", "name": "HP-SMOKE"}),
    ("mac_table", "sample_mac_table_cisco.txt", {"vendor": "cisco", "name": "SW-SMOKE"}),
    ("mac_table", "sample_mac_table_hp.txt", {"vendor": "hp", "name": "HP-SMOKE"}),
    ("arp", "sample_arp_cisco.txt", {"vendor": "cisco"}),
    ("arp", "sample_arp_unix.txt", {"vendor": "unix"}),
    ("arp", "sample_arp_windows.txt", {"vendor": "windows"}),
    ("forti_report", "sample_forti_traffic.csv", {}),
    ("forti_syslog", "sample_forti_events.cef", {"name": "SMOKE-SYSLOG-FW"}),
    ("forti_syslog", "@nodevname.log", {"name": "SMOKE-FALLBACK-FW"}),
    ("forti_event", "@event.json", {"name": "SMOKE-EVENT-FW"}),
    # F-11 multi-vendor syslog (the seed mapped these devices to Plant B; uploaded
    # for Plant A they are held as B-11 site_mismatch conflicts)
    ("syslog", "sample_syslog_asa.log", {"vendor": "cisco_asa", "name": "SMOKE-ASA"}),
    ("syslog", "sample_syslog_pfsense.log", {"vendor": "pfsense"}),
    ("syslog", "sample_syslog_panos.log", {"vendor": "auto"}),
    ("syslog", "@asa_xss.log", {"vendor": "cisco_asa", "name": f"asa-up{XSS}"}),
    ("baseline_comms", "sample_approved_comms.csv", {"baseline": "SMOKE"}),
    ("baseline_hosts", "sample_approved_hosts.csv", {"baseline": "SMOKE"}),
    ("baseline_assets", "sample_asset_inventory.csv", {"baseline": "SMOKE"}),
]


def test_upload(browser, base, shots, tmp):
    extra = {
        "@nodevname.log": tmp / "nodevname.log",
        "@event.json": tmp / "event.json",
        "@asa_xss.log": tmp / "asa_xss.log",
    }
    # bare ASA line (no hostname): its device name is the planted fallback
    extra["@asa_xss.log"].write_text(
        "%ASA-4-106023: Deny tcp src outside:198.51.100.77/40001 dst inside:10.10.1.20/23 "
        'by access-group "outside_access_in" [0x0, 0x0]\n')
    extra["@nodevname.log"].write_text(
        "date=2026-09-30 time=10:00:00 type=traffic subtype=forward srcip=10.0.3.50 "
        "dstip=10.0.1.10 srcport=50001 dstport=23 proto=6 action=accept policyid=98 service=TELNET\n")
    extra["@event.json"].write_text(json.dumps({
        "type": "traffic", "subtype": "forward", "srcip": "10.0.3.51", "dstip": "10.0.1.10",
        "srcport": 50002, "dstport": 23, "proto": 6, "action": "accept", "policyid": 97,
        "service": "TELNET"}))

    run = PageRun(browser, base, "upload", shots,
                  allowed=[("POST", r"/ingest/arp\?.*format_hint=windows", 422),
                           ("POST", r"/ingest/arp\?site=999999", 422)])
    p = run.page
    try:
        p.goto(base + "/ui/upload")
        # multi-site: no site -> refused client-side, no request sent
        sites = get_json(base, "/sites")
        p.wait_for_function("n => document.querySelectorAll('#site option').length === n + 1", arg=len(sites))
        p.select_option("#fileKind", "arp")
        p.select_option("#site", "")
        p.set_input_files("#file", str(SAMPLES / "sample_arp_cisco.txt"))
        sent = []
        p.on("request", lambda r: "/ingest/" in r.url and sent.append(r.url))
        p.click("#submitBtn")
        expect(p.locator("#result.error")).to_contain_text("Choose the site")
        if sent:
            run.errors.append(f"upload without a site was sent: {sent}")
        # unknown site -> the server's 422 detail
        p.evaluate("() => { const s = document.getElementById('site'); s.append(new Option('ghost', '999999')); s.value = '999999'; }")
        p.click("#submitBtn")
        expect(p.locator("#result.error")).to_contain_text("Unknown site")
        # log kinds: the picker is the OPTIONAL "map unknown devices to" site (phase 3)
        p.select_option("#fileKind", "syslog")
        if not p.locator("#siteGroup").is_visible() or "Map unknown devices" not in p.locator("#siteLabel").inner_text():
            run.errors.append("log upload: optional map-to-site picker not shown")
        p.select_option("#fileKind", "arp")
        # inline "+ New site" -> created and selected
        p.click("#siteNewBtn")
        p.fill("#siteNewName", "Upload Smoke Site")
        p.click("#siteCreateBtn")
        expect(p.locator("#siteHint")).to_contain_text("created")
        new = next((x for x in get_json(base, "/sites") if x["name"] == "Upload Smoke Site"), None)
        if new is None or p.locator("#site").input_value() != str(new["id"]):
            run.errors.append("inline-created site missing / not selected")
        plant_a = next(x["id"] for x in get_json(base, "/sites") if x["code"] == "plant-a")
        p.select_option("#site", str(plant_a))
        # level pickers come from GET /purdue-levels
        p.select_option("#fileKind", "firewall")
        levels = get_json(base, "/purdue-levels")["levels"]
        p.wait_for_function("n => document.querySelectorAll('#zoneFrom option').length === n + 1", arg=len(levels))
        texts = p.locator("#zoneFrom option").all_inner_texts()[1:]
        want = [f"{lv['label']} — {lv['name']}" for lv in sorted(levels, key=lambda x: -x["level"])]
        if texts != want:
            run.errors.append(f"zone options {texts} != /purdue-levels {want}")
        for kind, fname, opt in UPLOADS:
            p.select_option("#fileKind", kind)
            if "vendor" in opt:
                p.select_option("#vendor", opt["vendor"])
            if p.locator("#nameGroup").is_visible():
                p.fill("#deviceName", opt.get("name", ""))
            if "zf" in opt:
                p.select_option("#zoneFrom", opt["zf"])
                p.select_option("#zoneTo", opt["zt"])
            if "baseline" in opt:
                p.fill("#baselineName", opt["baseline"])
            path = extra.get(fname, SAMPLES / fname)
            p.set_input_files("#file", str(path))
            with p.expect_response(lambda r: "/ingest/" in r.url and r.request.method == "POST") as ri:
                p.click("#submitBtn")
            resp = ri.value
            expect(p.locator("#submitBtn")).to_have_text("Upload")
            cls = p.locator("#result").get_attribute("class")
            if resp.status != 200 or cls != "success":
                run.errors.append(f"upload {kind}/{fname}: HTTP {resp.status}, result={cls}: "
                                  f"{p.locator('#result').inner_text()[:300]}")
                continue
            body = resp.json()
            url = resp.url
            # multi-site: non-log uploads name their site; log uploads send the
            # picked site as "map unknown devices to" (phase 3) and show routing
            is_log = kind in ("forti_report", "forti_syslog", "forti_event", "syslog")
            q_site = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("site")
            if is_log:
                if q_site != [str(plant_a)]:
                    run.errors.append(f"upload {kind}: map site not sent for a log upload ({url})")
                rt = (body.get("stats") or {}).get("routing") or body.get("routing")
                if not rt or p.locator('[data-testid="routing-summary"]').count() != 1:
                    run.errors.append(f"upload {kind}: no routing summary")
                else:
                    for k in ("unmapped", "conflicts", "new_mappings", "site_conflicts"):
                        got = p.locator(f'[data-testid="routing-summary"] [data-stat="{k}"] b').inner_text()
                        if got != str(rt.get(k, 0)):
                            run.errors.append(f"upload {kind}: routing {k} shown {got} != {rt.get(k)}")
            if not is_log and (q_site != [str(plant_a)] or body.get("site_id") != plant_a):
                run.errors.append(f"upload {kind}: not stored in Plant A (sent {q_site}, got {body.get('site_id')})")
            # parameters actually sent
            if opt.get("name"):
                pname = {"fortigate_config": "firewall_name", "firewall": "firewall_device_name"}.get(kind, "device_name")
                if f"{pname}=" not in url:
                    run.errors.append(f"upload {kind}: {pname} not sent ({url})")
            if "zf" in opt and "purdue_zone_from=" not in url:
                run.errors.append(f"upload {kind}: purdue zones not sent ({url})")
            if kind == "firewall":
                for key in ("rules_disabled", "rules_skipped_negated_deny", "rules_skipped_ipv6",
                            "unresolved_object_groups", "unknown_port_names"):
                    if p.locator(f'tr[data-key="stats.{key}"]').count() != 1:
                        run.errors.append(f"upload firewall: stats.{key} not displayed")
            if kind == "forti_syslog" and fname.startswith("@"):
                if body.get("device_name") != "SMOKE-FALLBACK-FW":
                    run.errors.append(f"syslog device_name fallback not echoed: {body.get('device_name')}")
            if kind == "syslog":
                q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                if q.get("vendor_hint") != [opt["vendor"]]:
                    run.errors.append(f"syslog {fname}: vendor_hint sent {q.get('vendor_hint')}")
                st = body["stats"]
                summ = p.locator('[data-testid="syslog-summary"]')
                if summ.count() != 1:
                    run.errors.append(f"syslog {fname}: no summary")
                else:
                    for k in ("lines", "events_created", "duplicates_skipped", "parse_failures",
                              "findings_created", "escalations", "rule_hits_updated"):
                        got = summ.locator(f'[data-stat="{k}"] b').inner_text()
                        if got != str(st.get(k, 0)):
                            run.errors.append(f"syslog {fname}: {k} shown {got} != {st.get(k)}")
                    for v, c in st["by_vendor"].items():
                        cells = summ.locator(f'tr[data-vendor="{v}"] td').all_inner_texts()
                        if cells != [v, str(c["events_created"]), str(c["duplicates_skipped"])]:
                            run.errors.append(f"syslog {fname}: by_vendor row {v} = {cells}")
                    # B-11: lines of Plant B devices uploaded for Plant A are held as conflicts
                    if st["events_created"] + st["duplicates_skipped"] + st.get("conflicts", 0) == 0:
                        run.errors.append(f"syslog {fname}: nothing recognised")
                if fname.startswith("@") and st["events_created"] != 1:
                    run.errors.append(f"syslog {fname}: expected 1 new event, got {st['events_created']}")
                run.check_xss(f"(syslog {fname})")
                if fname == "sample_syslog_asa.log":
                    run.shot("syslog")
            if kind == "fortigate_config" and body.get("firewall_name") != "FW-SMOKE":
                run.errors.append(f"fortigate firewall_name not applied: {body.get('firewall_name')}")
            if kind == "forti_event" and body.get("device_name") != "SMOKE-EVENT-FW":
                run.errors.append(f"forti-event device_name not applied: {body.get('device_name')}")
        run.shot("desktop_after_success")

        # Error path: wrong ARP platform -> 422 with the handler's detail text shown.
        p.select_option("#fileKind", "arp")
        p.select_option("#vendor", "windows")
        p.set_input_files("#file", str(SAMPLES / "sample_arp_cisco.txt"))
        p.click("#submitBtn")
        expect(p.locator("#result.error")).to_contain_text("No ARP entries recognized")
        run.check_xss()
        run.check_no_hscroll()
        run.shot("desktop")
        run.mobile("#submitBtn")
    except Exception as exc:  # noqa: BLE001
        run.errors.append(f"exception: {exc!r}\n{traceback.format_exc()}")
    finally:
        run.close()
    return run.errors


# ---------------------------------------------------------------- findings --
def check_counts(run, base):
    p = run.page
    s = get_json(base, "/findings/summary")
    got_total = int(p.locator('[data-testid="count-open"] .summary-count').inner_text())
    if got_total != s["total_open"]:
        run.errors.append(f"open total {got_total} != summary {s['total_open']}")
    for sev in ("critical", "high", "medium", "low", "info"):
        got = int(p.locator(f'[data-testid="count-sev-{sev}"] .summary-count').inner_text())
        want = s["by_severity"].get(sev, 0)
        if got != want:
            run.errors.append(f"open {sev} {got} != summary {want}")
    for st in ("open", "acknowledged", "closed"):
        got = int(p.locator(f'[data-testid="count-status-{st}"] b').inner_text())
        want = s.get("by_status", {}).get(st, 0)
        if got != want:
            run.errors.append(f"status {st} {got} != summary {want}")
    for cat, want in s["by_category"].items():
        got = int(p.locator(f'[data-testid="count-cat"][data-key="{cat}"] b').inner_text())
        if got != want:
            run.errors.append(f"open {cat} {got} != summary {want}")
    return s


def wait_loaded(p, prev=None):
    if prev is None:
        p.wait_for_selector("body[data-loaded]", state="attached")
    else:
        p.wait_for_function("prev => document.body.dataset.loaded !== prev", arg=prev)
    return p.evaluate("() => document.body.dataset.loaded")


def api_total(base, query=""):
    """Total matching findings as reported by the X-Total-Count header."""
    with urllib.request.urlopen(f"{base}/findings?limit=1{('&' + query) if query else ''}", timeout=30) as r:
        return int(r.headers["X-Total-Count"])


def row_ids(p):
    return p.locator('[data-testid="finding-row"]').evaluate_all("rs => rs.map(r => r.dataset.id)")


def expect_total(run, p, n, what):
    info = p.locator("#page-info").inner_text()
    if f" of {n} · " not in info:
        run.errors.append(f"{what}: page-info {info!r}, expected 'of {n}' (X-Total-Count)")


def test_findings(browser, base, shots):
    run = PageRun(browser, base, "findings", shots)
    p = run.page
    try:
        p.goto(base + "/ui/findings")
        tok = wait_loaded(p)
        s = check_counts(run, base)
        total = api_total(base)
        expect_total(run, p, total, "initial")

        # Server-side paging at 25/page: page 2 rows differ from page 1.
        p.select_option("#page-size", "25")
        tok = wait_loaded(p, tok)
        if total <= 25:
            run.errors.append(f"only {total} findings - cannot exercise paging")
        else:
            page1 = row_ids(p)
            with p.expect_response(lambda r: "/findings?" in r.url and "offset=25" in r.url and "limit=25" in r.url):
                p.click("#page-next")
            tok = wait_loaded(p, tok)
            page2 = row_ids(p)
            info = p.locator("#page-info").inner_text()
            if len(page1) != 25 or not page2 or set(page1) & set(page2):
                run.errors.append(f"page 2 rows overlap/empty: p1={len(page1)} p2={len(page2)} shared={set(page1) & set(page2)}")
            if not info.startswith(f"26–{25 + len(page2)} of {total} "):
                run.errors.append(f"page 2 info {info!r}")
            expect_total(run, p, total, "page 2")
            run.shot("page2")
            p.click("#page-prev")
            tok = wait_loaded(p, tok)
            if row_ids(p) != page1:
                run.errors.append("prev did not return to page 1")

        # Group by every option (groups the current page; the note says so).
        for opt in p.locator("#group-by option").evaluate_all("os => os.map(o => o.value)"):
            p.select_option("#group-by", opt)
            if opt != "none":
                if p.locator('[data-testid="group-header"]').count() == 0:
                    run.errors.append(f"group-by {opt}: no group headers")
                if "This page only" not in p.locator("#list-note").inner_text():
                    run.errors.append(f"group-by {opt}: no 'current page' note")
            run.check_xss(f"(group-by {opt})")

        # Planted devname: filter server-side by that device, group by Device.
        dev = next((f["device_name"] for f in get_json(base, "/findings?limit=5000")
                    if f["device_name"] and "data-xss" in f["device_name"]), None)
        p.select_option("#group-by", "device_name")
        if dev is None:
            run.errors.append("planted devname finding not found via API")
        else:
            # No device filter control in the UI: search this page, walking pages until found.
            found = False
            for _ in range(total // 25 + 2):
                if p.locator('[data-testid="group-header"]', has_text="<img").count():
                    found = True
                    break
                if p.locator("#page-next").is_disabled():
                    break
                p.click("#page-next")
                tok = wait_loaded(p, tok)
            if not found:
                run.errors.append("device group with planted devname not rendered as text")
            else:
                p.locator('[data-testid="group-header"]', has_text="<img").locator(
                    "xpath=following-sibling::div[1]").click()
                expect(p.locator(".panel-title")).to_be_visible()
                run.check_xss("(detail panel)")
            run.shot("group_device")
        p.select_option("#group-by", "none")
        # N-12: search is server-side (q=), debounced, across all pages.
        for q in ("TELNET", "data-xss", "zz-no-such-finding-zz"):
            with p.expect_response(lambda r, q=q: "/findings?" in r.url
                                   and urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("q") == [q]):
                p.fill("#filter-search", q)
            tok = wait_loaded(p, tok)
            n = api_total(base, "q=" + urllib.parse.quote(q))
            expect_total(run, p, n, f"q={q}")
            if q == "data-xss" and n == 0:
                run.errors.append("server search for planted payload found nothing")
            if n == 0 and q not in p.locator("#empty-state").inner_text():
                run.errors.append(f"q={q}: empty state does not name the search")
            run.check_xss(f"(search {q})")
        p.fill("#filter-search", "")
        tok = wait_loaded(p, tok)
        expect_total(run, p, total, "search cleared")

        # Server-side filters: count comes from X-Total-Count.
        for sel, key, val in (("#filter-category", "category", "config_review"),
                              ("#filter-severity", "severity", "high"),
                              ("#filter-check", "check_name", "disabled_rule"),
                              ("#filter-status", "status", "open")):
            p.select_option(sel, val)
            tok = wait_loaded(p, tok)
            expect_total(run, p, api_total(base, f"{key}={val}"), f"{key}={val}")
            p.select_option(sel, "")
            tok = wait_loaded(p, tok)

        # Status changes: acknowledge one, close another.
        for new_status in ("acknowledged", "closed"):
            p.select_option("#filter-status", "open")
            tok = wait_loaded(p, tok)
            p.locator('[data-testid="finding-row"]').first.click()
            p.select_option("#edit-status", new_status)
            p.fill("#edit-ack-by", "smoke-test")
            p.fill("#edit-notes", f"smoke {new_status} <b>notes</b>")
            with p.expect_response(lambda r: "/status?" in r.url and r.request.method == "PATCH"):
                p.click("#save-btn")
            expect(p.locator("#save-status")).to_have_text("Saved.")
            expect(p.locator('[data-testid="panel-status"]')).to_have_text(new_status)
            p.wait_for_function("prev => document.body.dataset.loaded !== prev", arg=tok)
            tok = p.evaluate("() => document.body.dataset.loaded")
            s2 = check_counts(run, base)
            if s2["total_open"] != s["total_open"] - 1:
                run.errors.append(f"after {new_status}: open {s2['total_open']} != {s['total_open']} - 1")
            expect_total(run, p, api_total(base, "status=open"), f"open after {new_status}")
            s = s2
        for st in ("acknowledged", "closed"):
            p.click(f'[data-testid="count-status-{st}"]')
            tok = wait_loaded(p, tok)
            if p.locator(f".finding-row.st-{st}").count() == 0:
                run.errors.append(f"no row styled st-{st}")
        p.select_option("#filter-status", "")
        tok = wait_loaded(p, tok)

        # F-04: last seen / occurrences in list rows and the detail panel
        size = int(p.locator("#page-size").input_value())
        rows = get_json(base, f"/findings?limit={size}&offset=0")
        got = p.locator('[data-testid="finding-row"] .finding-time').evaluate_all("es => es.map(e => e.dataset.lastSeen || '')")
        if got != [f.get("last_seen") or "" for f in rows]:
            run.errors.append("row last_seen differs from GET /findings")
        if p.locator('[data-testid="occurrences"]').count() != sum(1 for f in rows if (f.get("occurrence_count") or 1) > 1):
            run.errors.append("occurrence badges != rows with occurrence_count > 1")
        p.locator('[data-testid="finding-row"]').first.click()
        want_occ = rows[0].get("occurrence_count")
        if p.locator('[data-testid="panel-occurrences"]').inner_text() != (str(want_occ) if want_occ is not None else "—"):
            run.errors.append("panel occurrences differ from the API")
        if p.locator('[data-testid="panel-last-seen"]').count() != 1:
            run.errors.append("panel last seen missing")
        # F-04 / N-02: Run reviews now -> run summary
        with p.expect_response(lambda r: r.url.endswith("/reviews/run") and r.request.method == "POST", timeout=120_000) as ri:
            p.click("#run-reviews-btn")
        r = ri.value.json()
        p.wait_for_selector('#run-result [data-testid="review-run"]')
        box = p.locator("#run-result")
        for k, want in (("total_findings", r["total_findings"]), ("failed_reviews", len(r["failed_reviews"])),
                        ("escalations", r["escalations"]), ("auto_resolved", sum(r["auto_resolved"].values())),
                        ("reviews", len(r["by_review"]))):
            got = box.locator(f'[data-stat="{k}"] b').inner_text()
            if got != str(want):
                run.errors.append(f"review run {k}: shown {got} != {want}")
        for name, n in r["auto_resolved"].items():
            cells = box.locator(f'tr[data-review="{name}"] td').all_inner_texts()
            if len(cells) < 3 or cells[2] != str(n):
                run.errors.append(f"auto-resolved {name}: {cells}")
        tok = wait_loaded(p, tok)
        check_counts(run, base)
        run.shot("reviews_run")
        p.click('#run-result button:has-text("Dismiss")')
        p.select_option("#group-by", "status")
        run.check_xss()
        run.check_no_hscroll()
        run.shot("desktop")
        run.mobile("body[data-loaded]")
        check_counts(run, base)
    except Exception as exc:  # noqa: BLE001
        run.errors.append(f"exception: {exc!r}\n{traceback.format_exc()}")
    finally:
        run.close()
    return run.errors


# ---------------------------------------------------------------- topology --
def plant(base, code="plant-a"):
    return next(x["id"] for x in get_json(base, "/sites") if x["code"] == code)


def test_topology(browser, base, shots):
    """/ui/topology is the console's Host Topology in standalone mode (one
    renderer): only that view, every API node on a card, planted text
    escaped, stale badge + history, level names, truncation notice."""
    site = plant(base)   # phase 2: the topology is drawn per site
    run = PageRun(browser, base, "topology", shots, site=site)
    p = run.page
    try:
        p.goto(base + "/ui/topology")
        p.wait_for_selector('[data-testid="host-node"]')
        if not p.evaluate("document.body.classList.contains('standalone')"):
            run.errors.append("/ui/topology is not in standalone mode")
        if p.locator(".nav-item:visible").count():
            run.errors.append("standalone topology still shows the console navigation")
        if not p.locator("#page-topology.active").count():
            run.errors.append("standalone page is not the Host Topology view")
        if p.locator('[data-testid="open-console"]').get_attribute("href") != "/ui#topology":
            run.errors.append("no link back to the full console")
        topo = get_json(base, f"/topology?site_id={site}")
        shown = p.locator('[data-testid="host-node"]').evaluate_all(
            "ns => ns.flatMap(n => (n.dataset.nodeIds || n.dataset.nodeId).split(' '))")
        if sorted(shown) != sorted(str(n["id"]) for n in topo["nodes"]):
            run.errors.append(f"{len(shown)} addresses on cards, API has {len(topo['nodes'])} nodes")
        planted = p.locator('[data-testid="host-node"]', has_text="<img")
        if planted.count() == 0:
            run.errors.append("planted device_type not rendered as text")
        else:
            planted.first.click()
            expect(p.locator("#topo-panel-body")).to_contain_text("Device type")
        run.check_xss("(planted node)")
        # F-09: stale badge (from /hosts) + address history in node detail
        ids = {n["id"] for n in topo["nodes"] if not n.get("external")}
        stale = [h for h in get_json(base, "/hosts") if h["stale"] and h["id"] in ids]
        p.wait_for_function("n => document.querySelectorAll('.host-node.stale').length >= n", arg=min(len(stale), 1))
        if not stale:
            run.errors.append("seed has no stale host")
        else:
            p.locator(f'[data-testid="host-node"][data-node-ids~="{stale[0]["id"]}"]').click()
            expect(p.locator('#topo-panel-body [data-testid="stale-badge"]').first).to_be_visible()
            hist = get_json(base, f"/hosts/{stale[0]['id']}/history")["history"]
            expect(p.locator("#topo-panel-body .host-history .detail-label").first).to_contain_text(
                f"Address history ({len(hist)})")
            if p.locator("#topo-panel-body .host-history [data-history-id]").count() != min(len(hist), 40):
                run.errors.append("history rows != API")
            run.shot("stale_node")
        # band titles from /purdue-levels
        for lv in get_json(base, "/purdue-levels")["levels"]:
            band = p.locator(f'.level-band[data-lane="{lv["level"]}"] .level-desc')
            if band.count() and band.inner_text() != lv["name"]:
                run.errors.append(f"band {lv['level']} desc {band.inner_text()!r} != {lv['name']!r}")
        # N-16: no notice for a complete result; "Partial view: N of M" when capped
        if p.locator("#topo-trunc").is_visible() != bool(topo.get("truncated")):
            run.errors.append("truncation notice state wrong for the real result")
        pat = re.compile(r"/topology\?site_id=\d+$")

        def fake(route):
            resp = route.fetch()
            body = resp.json()
            body.update(truncated=True, hosts_total=len(body["nodes"]) + 12345, sessions_total=len(body["edges"]) + 678)
            route.fulfill(response=resp, json=body)
        p.route(pat, fake)
        p.click("#topo-reload")
        expect(p.locator("#topo-trunc")).to_be_visible()
        txt = p.locator("#topo-trunc").inner_text()
        want = (f"{len(topo['nodes']):,} of {len(topo['nodes']) + 12345:,} hosts, "
                f"{len(topo['edges']):,} of {len(topo['edges']) + 678:,} sessions")
        if want not in txt:
            run.errors.append(f"truncation notice {txt!r} lacks {want!r}")
        run.shot("truncated")
        p.unroute(pat)
        p.click("#topo-reload")
        expect(p.locator("#topo-trunc")).to_be_hidden()
        p.wait_for_selector('[data-testid="host-node"]')
        # a node with sessions
        for i in range(min(p.locator('[data-testid="host-node"]').count(), 15)):
            p.locator('[data-testid="host-node"]').nth(i).click()
            if p.locator("#topo-panel-body .conn-item").count():
                break
        else:
            run.errors.append("no host node shows its sessions")
        run.check_xss()
        run.check_no_hscroll()
        run.shot("desktop")
        run.mobile('[data-testid="host-node"]')
        # the full console is not affected by the standalone view
        p.goto(base + "/ui")
        p.wait_for_load_state("networkidle")
        if p.evaluate("document.body.classList.contains('standalone')"):
            run.errors.append("/ui opened in standalone mode")
    except Exception as exc:  # noqa: BLE001
        run.errors.append(f"exception: {exc!r}\n{traceback.format_exc()}")
    finally:
        run.close()
    return run.errors


# ------------------------------------------------------------- attestation --
def test_attestation(browser, base, shots):
    run = PageRun(browser, base, "attestation", shots,
                  allowed=[("POST", r"/attestation$", 404)])
    p = run.page
    try:
        p.goto(base + "/ui/attestation")
        card = p.locator("#card-1_1")
        expect(card.locator(".status-pill")).to_contain_text("Attested")
        expect(card.locator(".proof-link")).to_contain_text("<img")     # filename shown as text
        if "<img" not in card.locator("textarea").input_value():
            run.errors.append("planted notes not pre-filled as text")
        run.check_xss("(initial)")

        # Submit for 1.1 (creates history) and 1.2 with a proof file.
        p.fill("#g-attester", "smoke <i>tester</i>")
        p.fill("#g-baseline", "B1")
        # always one site (owner 2026-10-13): no "All sites", a site is preselected
        opts = p.locator("#site-filter option").evaluate_all("os => os.map(o => o.value)")
        if not opts or "" in opts:
            run.errors.append(f"attestation site options {opts}")
        plant_a = next(x["id"] for x in get_json(base, "/sites") if x["code"] == "plant-a")
        plant_b = next(x["id"] for x in get_json(base, "/sites") if x["code"] == "plant-b")
        if p.locator("#site-filter").input_value() == str(plant_a):
            with p.expect_response(lambda r: "/attestation?site_id=" in r.url):
                p.select_option("#site-filter", str(plant_b))
        with p.expect_response(lambda r: "/attestation?site_id=" in r.url):
            p.select_option("#site-filter", str(plant_a))
        for row, proof in (("1_1", None), ("1_2", SAMPLES / "sample_approved_hosts.csv")):
            c = p.locator(f"#card-{row}")
            c.locator("textarea").fill(f"smoke attestation {row} <script>x</script>")
            if proof:
                c.locator('input[type="file"]').set_input_files(str(proof))
            with p.expect_response(lambda r: r.url.endswith("/attestation") and r.request.method == "POST") as ri:
                c.locator("button.primary").click()
            if ri.value.status != 201:
                run.errors.append(f"attestation {row}: HTTP {ri.value.status}")
            expect(c.locator(".save-status")).to_have_text("Saved ✓")
            expect(c.locator(".status-pill")).to_contain_text("Attested 0d ago")
        c = p.locator("#card-1_1")
        c.locator(".history-toggle").click()
        expect(c.locator(".history-table")).to_contain_text("smoke <i>tester</i>")
        expect(c.locator(".history-table")).to_contain_text("alice<img")
        # .first: the card can already hold proof links from earlier runs on the same DB
        expect(p.locator("#card-1_2 .proof-link", has_text="sample_approved_hosts.csv").first).to_be_visible()
        mine = [a for a in get_json(base, f"/attestation?site_id={plant_a}") if a["attested_by"] == "smoke <i>tester</i>"]
        if len(mine) < 2:
            run.errors.append(f"attestations not stored in Plant A: {len(mine)}")

        # Error path: unknown baseline -> 404 detail shown
        p.fill("#g-baseline", "no-such-baseline")
        c3 = p.locator("#card-1_3")
        c3.locator("button.primary").click()
        expect(c3.locator(".save-status.err")).to_contain_text("not found")
        p.fill("#g-baseline", "B1")

        run.check_xss()
        run.check_no_hscroll()
        run.shot("desktop")
        run.mobile("#card-1_6")
    except Exception as exc:  # noqa: BLE001
        run.errors.append(f"exception: {exc!r}\n{traceback.format_exc()}")
    finally:
        run.close()
    return run.errors


# ------------------------------------------------------------- fw-topology --
def test_fw_topology(browser, base, shots):
    site = plant(base)   # phase 2: the builder works on one site
    run = PageRun(browser, base, "fw_topology", shots, site=site)
    p = run.page
    try:
        p.goto(base + "/ui/fw-topology")
        p.wait_for_selector("body[data-loaded]", state="attached")
        st = get_json(base, f"/topology/state?site_id={site}")
        cols = p.locator('[data-testid="fw-column"]').count()
        if cols != st["firewall_count"]:
            run.errors.append(f"{cols} firewall columns, API reports {st['firewall_count']}")
        if st["firewall_count"] == 0:
            run.errors.append("no firewalls in /topology/state - upload step should have added some")
            return run.errors

        # Confirm a proposed link if any (FW-OT + FW-SMOKE share subnets).
        if p.locator('[data-testid="proposal-card"]').count():
            with p.expect_response(lambda r: "/topology/confirm-link" in r.url) as ri:
                p.locator('[data-testid="proposal-card"] .btn-confirm').first.click()
            if ri.value.status != 200:
                run.errors.append(f"confirm-link HTTP {ri.value.status}")
            p.wait_for_selector(".iface-card.linked")

        # Interface detail + label save (zone label with markup must stay text)
        card = p.locator('[data-testid="iface-card"]').first
        name = card.locator(".iface-name").inner_text()
        card.click()
        expect(p.locator("#rp-title")).to_contain_text(name)
        p.select_option("#rp-side", "inside")
        p.fill("#rp-zone", 'OT <b>Floor</b> "A"')
        p.select_option("#rp-purdue", "2")
        with p.expect_response(lambda r: "/topology/set-interface-side" in r.url) as ri:
            p.click("#rp-save-btn")
        if ri.value.status != 200:
            run.errors.append(f"set-interface-side HTTP {ri.value.status}")
        expect(p.locator("#rp-save-msg")).to_have_text("Saved ✓")
        expect(p.locator(".badge-zone", has_text='OT <b>Floor</b> "A"')).to_have_count(1)

        # Firewall chain
        with p.expect_response(lambda r: "/topology/set-upstream" in r.url) as ri:
            p.locator("text=Save firewall chain").click()
        if ri.value.status != 200:
            run.errors.append(f"set-upstream HTTP {ri.value.status}")
        expect(p.locator("#rp-chain-msg")).to_contain_text("Saved ✓")

        # Header actions
        for btn, path in (("#suggest-btn", "/topology/suggest-purdue"), ("#checks-btn", "/topology/run-checks")):
            with p.expect_response(lambda r, path=path: path in r.url) as ri:
                p.click(btn)
            if ri.value.status != 200:
                run.errors.append(f"{path} HTTP {ri.value.status}")
        expect(p.locator("#action-result")).to_contain_text("Cross-FW checks done")

        # multi-site: the column view follows the site filter; uploads need a site
        plant_a = next(x["id"] for x in get_json(base, "/sites") if x["code"] == "plant-a")
        plant_b = next(x["id"] for x in get_json(base, "/sites") if x["code"] == "plant-b")
        if p.locator("#site-filter").input_value() == str(plant_a):
            with p.expect_response(lambda r: "/topology/state?site_id=" in r.url):
                p.select_option("#site-filter", str(plant_b))
        with p.expect_response(lambda r: "/topology/state?site_id=" in r.url):
            p.select_option("#site-filter", str(plant_a))
        p.wait_for_load_state("networkidle")
        want = get_json(base, f"/topology/state?site_id={plant_a}")["firewall_count"]
        got = p.locator('[data-testid="fw-column"]').count()
        if got != want:
            run.errors.append(f"Plant A: {got} firewall columns, API reports {want}")
        # FW-aware pcap upload + confirm
        with p.expect_response(lambda r: "/ingest/pcap-fw" in r.url and "site=" in r.url) as ri:
            p.set_input_files("#pcap-file", str(SAMPLES / "modbus_sample.pcap"))
        if ri.value.status != 200:
            run.errors.append(f"pcap-fw HTTP {ri.value.status}")
        expect(p.locator('[data-testid="pcap-result"]')).to_be_visible()
        confirm = p.locator('[data-testid="pcap-result"] .btn-confirm')
        if confirm.count():
            with p.expect_response(lambda r: "/confirm" in r.url and "/ingest/pcap/" in r.url) as ri:
                confirm.click()
            if ri.value.status != 200:
                run.errors.append(f"pcap confirm HTTP {ri.value.status}")
        run.check_xss()
        run.check_no_hscroll()
        run.shot("desktop")
        run.mobile("body[data-loaded]")
    except Exception as exc:  # noqa: BLE001
        run.errors.append(f"exception: {exc!r}\n{traceback.format_exc()}")
    finally:
        run.close()
    return run.errors


# ------------------------------------------------------------- site filter --
def test_site_filters(browser, base, shots):
    """findings.html and /ui/topology follow the shared site filter."""
    run = PageRun(browser, base, "site_filters", shots)
    p = run.page
    try:
        plant_b = next(x["id"] for x in get_json(base, "/sites") if x["code"] == "plant-b")
        p.goto(base + "/ui/findings")
        p.wait_for_selector("body[data-loaded]", state="attached")
        names = p.locator("#site-filter option").all_inner_texts()
        if "All sites" in names or not {"Plant A", "Plant B"} <= set(names):
            run.errors.append(f"findings site options {names}")
        if not p.locator("#site-filter").input_value():
            run.errors.append("findings: no site preselected")
        with p.expect_response(lambda r: "/findings/summary?site_id=" in r.url):
            p.select_option("#site-filter", str(plant_b))
        p.wait_for_load_state("networkidle")
        want = get_json(base, f"/findings/summary?site_id={plant_b}")["total_open"]
        got = int(p.locator('[data-testid="count-open"] .summary-count').inner_text())
        if got != want:
            run.errors.append(f"Plant B open findings shown {got} != API {want}")
        run.shot("findings_plant_b")
        # the choice is shared (localStorage) with the other pages
        p.goto(base + "/ui/topology")
        p.wait_for_load_state("networkidle")
        if p.locator("#site-select").input_value() != str(plant_b):
            run.errors.append("site choice not shared with /ui/topology")
        n = len(get_json(base, f"/topology?site_id={plant_b}")["nodes"])
        p.wait_for_function("n => [...document.querySelectorAll('[data-testid=host-node]')].flatMap("
                            "x => (x.dataset.nodeIds || '').split(' ')).length === n", arg=n)
        run.shot("topology_plant_b")
        # always one site: no "All sites" option on /ui/topology or fw-topology
        if p.locator('#site-select option[value=""]').count():
            run.errors.append("/ui/topology still offers 'All sites'")
        p.goto(base + "/ui/fw-topology")
        p.wait_for_selector("body[data-loaded]", state="attached")
        p.wait_for_load_state("networkidle")
        if p.locator("#site-filter").input_value() != str(plant_b) or p.locator('#site-filter option[value=""]').count():
            run.errors.append("fw-topology: shared site not selected / 'All sites' offered")
        # nothing remembered (or a deleted site): the default / first site is chosen
        p.evaluate("() => { try { localStorage.setItem('iasc_site', '999999'); } catch (e) {} }")
        p.goto(base + "/ui/findings")
        p.wait_for_selector("body[data-loaded]", state="attached")
        if not p.locator("#site-filter").input_value():
            run.errors.append("findings: no site chosen for an unknown remembered site")
        # isolation: the same config in both plants -> one FW-OT per site
        ids = [f["id"] for code in ("plant-a", "plant-b")
               for f in get_json(base, f"/topology/firewalls?site_id={plant(base, code)}")["firewalls"]
               if f["name"] == "FW-OT"]
        if len(ids) != 2 or ids[0] == ids[1]:
            run.errors.append(f"FW-OT is not one independent firewall per site: {ids}")
        run.check_xss()
    except Exception as exc:  # noqa: BLE001
        run.errors.append(f"exception: {exc!r}\n{traceback.format_exc()}")
    finally:
        run.close()
    return run.errors


# ------------------------------------------------- B-23: race + keyboard --
def test_b23(browser, base, shots):
    """A late answer for the previously selected site never overwrites the
    new site's view (findings.html, topology.html); finding rows, topology
    nodes and FW interface cards work from the keyboard (Enter / Space)."""
    a_id, b_id = plant(base, "plant-a"), plant(base, "plant-b")
    run = PageRun(browser, base, "b23", shots, site=a_id)
    p = run.page

    def race(path, url_re, ready, reload="#reload-btn", site_sel="#site-filter"):
        p.goto(base + path)
        ready()
        held = []
        pat = re.compile(url_re % a_id)
        matcher = lambda u: bool(pat.search(u))
        p.route(matcher, lambda route: held.append(route))
        p.click(reload)
        for _ in range(100):
            if held:
                break
            p.wait_for_timeout(50)
        if not held:
            run.errors.append(f"{path}: no Plant A request was in flight")
        p.select_option(site_sel, str(b_id))
        p.wait_for_load_state("networkidle")
        ready()
        for r in held:
            try:
                r.continue_()
            except Exception:  # noqa: BLE001 - aborted by the page (superseded)
                pass
        p.unroute(matcher)
        p.wait_for_timeout(1200)

    try:
        # findings.html: counts + rows are Plant B's
        race("/ui/findings", r"/findings(/summary)?\?(.*&)?site_id=%d(&|$)",
             lambda: p.wait_for_selector("body[data-loaded]", state="attached"))
        want = get_json(base, f"/findings/summary?site_id={b_id}")["total_open"]
        got = int(p.locator('[data-testid="count-open"] .summary-count').inner_text())
        if got != want:
            run.errors.append(f"findings.html: open count {got} != Plant B {want} after a late Plant A answer")
        size = int(p.locator("#page-size").input_value())
        api_ids = [str(f["id"]) for f in get_json(base, f"/findings?limit={size}&offset=0&site_id={b_id}")]
        if row_ids(p) != api_ids:
            run.errors.append("findings.html: rows are not Plant B's after the site switch")
        # keyboard: Tab to a row, Enter selects it (panel), Space selects the next
        p.focus("#filter-search")
        rid = None
        for _ in range(60):
            p.keyboard.press("Tab")
            rid = p.evaluate("() => document.activeElement && document.activeElement.dataset.testid === 'finding-row' ? document.activeElement.dataset.id : null")
            if rid:
                break
        if rid is None:
            run.errors.append("findings.html: Tab never reached a finding row")
        else:
            p.keyboard.press("Enter")
            expect(p.locator(f'[data-testid="finding-row"][data-id="{rid}"]')).to_have_class(re.compile(r"\bselected\b"))
            if p.evaluate("() => document.activeElement.dataset.id") != rid:
                run.errors.append("findings.html: focus lost after Enter on a finding row")
            p.keyboard.press("Tab")
            nxt = p.evaluate("() => document.activeElement.dataset.testid === 'finding-row' ? document.activeElement.dataset.id : null")
            if nxt:
                p.keyboard.press(" ")
                expect(p.locator(f'[data-testid="finding-row"][data-id="{nxt}"]')).to_have_attribute("aria-pressed", "true")
        run.shot("findings_race_keyboard")

        # topology.html: nodes are Plant B's (hosts paging uses the captured site)
        p.select_option("#site-filter", str(a_id))
        p.wait_for_load_state("networkidle")
        race("/ui/topology", r"/(topology|hosts)\?(.*&)?site_id=%d(&|$)",
             lambda: p.wait_for_load_state("networkidle"), reload="#topo-reload", site_sel="#site-select")
        nodes = get_json(base, f"/topology?site_id={b_id}")["nodes"]
        shown = sorted(p.locator('[data-testid="host-node"]').evaluate_all(
            "ns => ns.flatMap(n => (n.dataset.nodeIds || n.dataset.nodeId).split(' '))"))
        if shown != sorted(str(n["id"]) for n in nodes):
            run.errors.append("/ui/topology: nodes are not Plant B's after the site switch")
        node = p.locator('[data-testid="host-node"]').first
        nid = node.get_attribute("data-node-id")
        node.focus()
        p.keyboard.press(" ")
        sel = p.locator(f'[data-testid="host-node"][data-node-id="{nid}"]')
        if sel.get_attribute("aria-pressed") != "true" or "selected" not in (sel.get_attribute("class") or ""):
            run.errors.append("/ui/topology: Space on a host node did not select it")
        run.shot("topology_race_keyboard")

        # fw-topology.html: interface cards (Plant A has FW-OT)
        p.goto(base + "/ui/fw-topology")
        p.wait_for_selector("body[data-loaded]", state="attached")
        cards = p.locator('[data-testid="iface-card"]')
        if cards.count():
            c = cards.first
            c.focus()
            p.keyboard.press("Enter")
            if c.get_attribute("aria-pressed") != "true":
                run.errors.append("fw-topology.html: Enter on an interface card did not select it")
        run.check_xss()
    except Exception as exc:  # noqa: BLE001
        run.errors.append(f"exception: {exc!r}\n{traceback.format_exc()}")
    finally:
        run.close()
    return run.errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base_url")
    ap.add_argument("--shots", default=str(Path(tempfile.gettempdir()) / "ui_smoke_shots"))
    ap.add_argument("--headed", action="store_true")
    a = ap.parse_args()
    base = a.base_url.rstrip("/")
    Path(a.shots).mkdir(parents=True, exist_ok=True)
    get_json(base, "/health")

    results = {}
    with sync_playwright() as pw, tempfile.TemporaryDirectory() as tmp:
        browser = pw.chromium.launch(headless=not a.headed)
        for name, fn in (("upload", lambda: test_upload(browser, base, a.shots, Path(tmp))),
                         ("findings", lambda: test_findings(browser, base, a.shots)),
                         ("topology", lambda: test_topology(browser, base, a.shots)),
                         ("attestation", lambda: test_attestation(browser, base, a.shots)),
                         ("fw-topology", lambda: test_fw_topology(browser, base, a.shots)),
                         ("site-filters", lambda: test_site_filters(browser, base, a.shots)),
                         ("b23", lambda: test_b23(browser, base, a.shots))):
            results[name] = fn()
            print(f"{'PASS' if not results[name] else 'FAIL'}  /ui/{name}")
            for e in results[name]:
                print(f"      - {e}")
        browser.close()
    print(f"screenshots: {a.shots}")
    sys.exit(1 if any(results.values()) else 0)


if __name__ == "__main__":
    main()
