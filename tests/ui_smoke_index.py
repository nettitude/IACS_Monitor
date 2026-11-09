#!/usr/bin/env python
"""
Browser smoke test for the unified console (ui/index.html). NOT a pytest
module (no test_ prefix) - run it standalone against a running server:

    python tests/ui_demo_server.py --db /tmp/ui.db --port 8765 &
    python tests/ui_smoke_index.py http://127.0.0.1:8765 [--shots DIR]

Run it against a freshly seeded, throwaway demo DB: it writes to the
database (uploads, attestations, status changes, an extra FortiGate config)
and some assertions assume the seed state.

It opens <url>/ui in headless Chromium, visits every sidebar section and for
each one: records console errors / page errors / failed or 4xx-5xx responses,
checks that no planted XSS payload executed (window.__xss, img[data-xss]),
checks the key numbers/tables against the API, and saves a screenshot.
It also exercises: finding status change (closed styling), attestation save
twice (second demotes the first) plus an error path, inventory save,
reachability filters + cell detail + host path lookup, the firewall
disabled-rule drill-down, and the FW topology builder (select interface,
confirm a proposed link). Newer features: multi-vendor syslog upload
(/ingest/syslog, per-vendor summary), findings last seen / occurrences and
"Run reviews now", stale badges + address history (topology and inventory)
and "Mark stale hosts", NAT counts / drill-down per firewall, rule
"last matched" (relative time + tooltip, sort, never-matched permits), NAT on
reachability paths and the host path lookup (incl. nat_destination), and the
Reports & Diagnostics page (compliance PDF link built from the form,
diagnostics, review run). Finally it re-checks every section at phone width
for horizontal page overflow.

Multi-site (phase 1): the seed has sites "Plant A" / "Plant B".  The run
checks the global site selector (options from /sites, every list follows
it - topology nodes, firewall device cards and findings totals match the
API's ?site_id= answers - and the choice survives a reload via
localStorage), the required site picker on uploads (client-side refusal
without a site, server 422 for an unknown site, inline "+ New site"
creation, log kinds hide the picker), and that the FW-topology PCAP upload
and attestation forms send their site.

Multi-site (phase 2): the seed loads the SAME FortiGate config / ARP table /
PCAP into Plant B too (overlapping IPs, a firewall "FW-OT" in each site).
The section run happens with Plant A selected (analysis pages work on one
site; API cross-checks mirror the UI's ?site_id=), and the sites section
checks isolation (each site its own FW-OT / hosts / findings) and, always one
site (owner 2026-10-13), that the selector has no "All sites", per-site pages
never ask for a site, the report link is scoped to the site, and an unknown
remembered site falls back to the default / first site.

Multi-site (phase 3): log uploads are routed per device.  The ingest
section checks the routing summary (per-site table, held / new mappings /
conflicts) and that the optional "Map unknown devices to" site is sent; the
devices section checks the registered-device table against /site-devices,
the nav badge against the pending held lines, adds a device, and maps the
seed's unknown "rogue-fw9" to Plant B from the "Unmapped devices" list
(replay result shown, the row and the badge go away).
B-11: the "Conflicts" list matches GET /site-devices/conflicts (the seeded
serial conflict and site mismatch, plus the site-mismatch lines the ingest
section's Plant A uploads of Plant B devices add), the badge counts unmapped
+ conflict lines, and the seeded serial conflict is resolved as "Same device -
replaced unit" via the in-page confirmation (keyboard), checking the replay
summary, the registry serial and the recorded resolution.
B-12: the seeded a-p HA cluster FG-OT-PERIMETER-01 shows its HA badge and
both member serials; a third member is added via "Add member serial" and its
in-row confirmation (keyboard: Escape cancels, focus returns).

Access Review (access-path review phase 3 UI): the accessreview section
checks the paths / unexplained-flow rows against GET /access-paths, the
"Generate report (N lines)" count against counts.report_include, the client
side filters (direction, flag, cross-boundary re-query), classifying a row
via its select (persisted with the remembered "classified by"), the "In
report" toggle, a bulk classification of two rows (selection kept), saving
a reviewer note, keyboard use (Tab to a row expander + Enter, a sort header),
and that the page never says "unused".

NOTE: it mutates the target DB (it may ingest a second FortiGate config with
disabled policies so the disabled-rule drill-down has data). Only point it
at a throwaway demo database.

Exit status is non-zero if any check fails.
"""
import argparse
import tempfile
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SECTIONS = ["ingest", "devices", "overview", "findings", "topology", "nettopo", "fwports", "extcomms", "zones", "fw", "fwtopo", "mgmt", "reach", "accessreview", "iec", "shadow", "attest", "assets", "system"]
SYSLOG_SAMPLES = [("sample_syslog_asa.log", "cisco_asa"), ("sample_syslog_pfsense.log", "pfsense"),
                  ("sample_syslog_panos.log", "auto")]
PERMIT = {"permit", "accept", "allow", "pass"}

# Two disabled FortiGate policies (same shape as tests/test_disabled_rules.py)
_DISABLED = """config firewall policy
    edit 5
        set name "Legacy-IT-to-OT-Any"
        set srcintf "port3"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set logtraffic disable
        set status disable
    next
    edit 6
        set name "Old-Block-Telnet"
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "OT-PLCs"
        set service "TELNET"
        set action deny
        set status disable
    next
"""


class SiteReq:
    """APIRequestContext wrapper: GETs carry ?site_id=<owner.cur_site> like
    the console's withSiteFilter (unless the path names a site already)."""

    def __init__(self, req, owner):
        self._req, self._owner = req, owner

    def get(self, url, **kw):
        sid = self._owner.cur_site
        path = urllib.parse.urlparse(url).path
        if sid and "site_id=" not in url and not path.startswith("/sites"):
            url += ("&" if "?" in url else "?") + f"site_id={sid}"
        return self._req.get(url, **kw)

    def __getattr__(self, name):
        return getattr(self._req, name)


class Smoke:
    def __init__(self, base, shots):
        self.base = base.rstrip("/")
        self.shots = Path(shots)
        self.shots.mkdir(parents=True, exist_ok=True)
        self.failures = []
        self.passed = []
        self.events = []          # (kind, text) collected since last reset
        self.allowed = []         # substrings of expected error responses
        self.cur_site = None      # site id the console has selected (None = all sites)

    # ------------------------------------------------------------ plumbing
    def check(self, cond, msg):
        if not cond:
            self.failures.append(msg)
            print("  FAIL:", msg)
        return cond

    def hook(self, page):
        page.on("console", lambda m: m.type == "error" and self.events.append(("console", m.text)))
        page.on("pageerror", lambda e: self.events.append(("pageerror", str(e))))
        page.on("requestfailed", lambda r: self.events.append(("requestfailed", f"{r.method} {r.url} {r.failure}")))
        page.on("response", lambda r: r.status >= 400 and self.events.append(("http", f"{r.status} {r.request.method} {r.url}")))

    def drain(self, section):
        bad = []
        for kind, text in self.events:
            if any(a in text for a in self.allowed):
                continue
            # B-23: a superseded load is aborted on purpose (AbortController)
            if kind == "requestfailed" and "ERR_ABORTED" in text:
                continue
            # the browser also logs a console error for every 4xx; judged via the http event
            if kind == "console" and "Failed to load resource" in text and any(a in t for _, t in self.events for a in self.allowed):
                continue
            bad.append(f"{kind}: {text}")
        self.events.clear()
        self.allowed = []
        self.check(not bad, f"[{section}] unexpected errors: {bad}")

    def xss_clean(self, page, section):
        fired = page.evaluate("() => window.__xss")
        imgs = page.locator("img[data-xss]").count()
        self.check(fired in (None, 0) and imgs == 0, f"[{section}] XSS payload executed/injected (window.__xss={fired}, img[data-xss]={imgs})")

    def goto(self, page, section):
        page.locator(f'.nav-item[data-page="{section}"]').click()
        page.wait_for_selector(f"#page-{section}.active")
        # wait for the section's status line to settle
        page.wait_for_function(
            """(s) => { const e = document.getElementById(s + '-status');
                       return !e || !/Loading|Computing|Analysing/.test(e.textContent); }""",
            arg=section, timeout=20000)
        page.wait_for_load_state("networkidle")

    def shot(self, page, name):
        page.screenshot(path=str(self.shots / f"{name}.png"), full_page=True)

    def api(self, req, path):
        r = req.get(self.base + path)
        assert r.ok, f"GET {path} -> {r.status}"
        return r.json()

    def api_all(self, req, path):
        """GET without the console's ?site_id= (global lists: conflicts, audit)."""
        raw = getattr(req, "_req", req)
        r = raw.get(self.base + path)
        assert r.ok, f"GET {path} -> {r.status}"
        return r.json()

    # -------------------------------------------------------------- setup
    def seed_disabled_rules(self, req):
        if self.api(req, "/firewall-rules?enabled=false"):
            return
        sample = ROOT / "sample_data" / "sample_fortigate_config.txt"
        if not sample.exists():
            print("  (no sample FortiGate config; disabled-rule drill-down will show the empty state)")
            return
        cfg = sample.read_text().replace("config firewall policy\n", _DISABLED, 1)
        r = req.post(self.base + "/ingest/fortigate-config?firewall_name=FW-LEGACY&site=plant-a",
                     multipart={"file": {"name": "legacy.conf", "mimeType": "text/plain", "buffer": cfg.encode()}})
        print("  seeded FW-LEGACY with disabled policies ->", r.status)

    def site_id(self, req, code):
        return next(x["id"] for x in self.api(req, "/sites") if x["code"] == code)

    # ----------------------------------------------------------- sections
    def s_ingest(self, page, req):
        self.check(page.locator("#ing-kind option").count() >= 10, "[ingest] kind options missing")
        self.check(page.locator("#file-banner").is_hidden(), "[ingest] file:// banner shown on an http page")
        info = page.locator("#api-base-info").inner_text()
        self.check(self.base.split("//")[1] in info or "override" in info.lower(), f"[ingest] API base info wrong: {info!r}")
        kinds = page.locator("#ing-kind option").evaluate_all("os => os.map(o => o.value)")
        self.check("forti_syslog" in kinds and "syslog" in kinds, f"[ingest] syslog kinds missing: {kinds}")
        # F-11: the three vendor samples through /ingest/syslog, summary per vendor
        page.locator("#ing-kind").select_option("syslog")
        hints = page.locator("#ing-vendor option").evaluate_all("os => os.map(o => o.value)")
        self.check(hints == ["auto", "fortinet", "cisco_asa", "pfsense", "panos"], f"[ingest] vendor_hint options {hints}")
        # 2026-10-19: standalone FortiSwitch configs through the switch form
        page.locator("#ing-kind").select_option("switch")
        sw_hints = page.locator("#ing-vendor option").evaluate_all("os => os.map(o => o.value)")
        self.check("fortinet" in sw_hints, f"[ingest] switch vendor_hint options {sw_hints} (FortiSwitch missing)")
        page.locator("#ing-kind").select_option("syslog")
        self.check("Fallback device name" in page.locator("#ing-device-label").inner_text(), "[ingest] syslog device_name fallback field missing")
        for name, hint in SYSLOG_SAMPLES:
            page.locator("#ing-vendor").select_option(hint)
            page.locator("#ing-device-name").fill("SMOKE-SYSLOG" if hint == "cisco_asa" else "")
            page.locator("#ing-file").set_input_files(str(ROOT / "sample_data" / name))
            with page.expect_response(lambda r: "/ingest/syslog" in r.url and r.request.method == "POST") as ri:
                page.locator("#ing-submit-btn").click()
            resp = ri.value
            q = urllib.parse.parse_qs(urllib.parse.urlparse(resp.url).query)
            self.check(q.get("vendor_hint") == [hint], f"[ingest] {name}: vendor_hint sent {q.get('vendor_hint')}")
            if hint == "cisco_asa":
                self.check(q.get("device_name") == ["SMOKE-SYSLOG"], f"[ingest] {name}: device_name not sent")
            if not self.check(resp.status == 200, f"[ingest] {name}: HTTP {resp.status}"):
                continue
            st = resp.json()["stats"]
            page.wait_for_selector("#ing-summary .stat-bar", timeout=10000)
            for k in ("lines", "events_created", "duplicates_skipped", "parse_failures", "findings_created", "escalations", "rule_hits_updated"):
                got = page.locator(f'#ing-summary [data-stat="{k}"] b').inner_text()
                self.check(got == str(st.get(k, 0)), f"[ingest] {name}: {k} shown {got} != {st.get(k)}")
            for v, c in st["by_vendor"].items():
                cells = page.locator(f'#ing-summary tr[data-vendor="{v}"] td').all_inner_texts()
                self.check(cells == [v, str(c["events_created"]), str(c["duplicates_skipped"])], f"[ingest] {name}: by_vendor {v} row {cells}")
            self.check(page.locator("#ing-summary [data-testid=by-vendor] tbody tr").count() == len(st["by_vendor"]), f"[ingest] {name}: by_vendor rows")
            # phase 3: routing summary (optional map site = the picker, Plant A here)
            rt = st.get("routing") or {}
            pick = page.locator("#ing-site").input_value()
            self.check(q.get("site") == ([pick] if pick else None), f"[ingest] {name}: map site sent {q.get('site')} (picker {pick!r})")
            if self.check(page.locator("#ing-summary [data-testid=routing-summary]").count() == 1, f"[ingest] {name}: no routing summary"):
                for k in ("unmapped", "conflicts", "new_mappings", "site_conflicts"):
                    got = page.locator(f'#ing-summary [data-testid=routing-summary] [data-stat="{k}"] b').inner_text()
                    self.check(got == str(rt.get(k, 0)), f"[ingest] {name}: routing {k} shown {got} != {rt.get(k)}")
                rows = page.locator("#ing-summary [data-testid=routing-by-site] tbody tr").count()
                self.check(rows == len(rt.get("routed") or {}), f"[ingest] {name}: routing rows {rows} != {rt.get('routed')}")
            # B-11: lines of devices registered to Plant B are held as site_mismatch conflicts
            self.check(st["events_created"] + st["duplicates_skipped"] + st.get("conflicts", 0) > 0, f"[ingest] {name}: nothing recognised {st}")
        self.shot(page, "ingest_syslog")
        # bad vendor_hint -> 422 detail shown (option injected to reach the server check)
        self.allowed.append("/ingest/syslog")
        page.evaluate("() => { const s = document.getElementById('ing-vendor'); s.append(new Option('bogus', 'bogus')); s.value = 'bogus'; }")
        page.locator("#ing-submit-btn").click()
        page.wait_for_selector("#ing-result.err", timeout=10000)
        self.check("vendor_hint must be one of" in page.locator("#ing-result").inner_text(), "[ingest] 422 vendor_hint detail not shown")
        self.check(page.locator("#ing-summary").is_hidden(), "[ingest] stale summary shown after an error")

    def s_devices(self, page, req):
        """Phase 3: device registry + unmapped queue."""
        # the page's status line is #dev-status (goto() looks for #devices-status)
        page.wait_for_function("() => { const e = document.getElementById('dev-status'); "
                               "return e && e.textContent && !/Loading/.test(e.textContent); }", timeout=20000)
        devs = self.api(req, "/site-devices")          # ?site_id= like the console
        rows = page.locator("[data-testid=dev-table] tbody tr")
        self.check(rows.count() == len(devs), f"[devices] table rows {rows.count()} != /site-devices {len(devs)}")
        names = rows.evaluate_all("rs => rs.map(r => r.dataset.device)")
        self.check(sorted(names) == sorted(d["device_name"] for d in devs), f"[devices] names {names}")
        um = self.api(req, "/site-devices/unmapped")
        cf = self.api_all(req, "/site-devices/conflicts")
        badge = page.locator("[data-testid=unmapped-badge]")
        held = um["pending_lines"] + cf["pending_conflicts"]
        if held:
            self.check(badge.is_visible() and badge.inner_text() == str(held),
                       f"[devices] badge {badge.inner_text()!r} != unmapped + conflicts {held}")
        self.devices_conflicts(page, req, cf, badge)
        self.devices_ha(page, req)
        keys = page.locator("[data-testid=unmapped-table] tbody tr").evaluate_all("rs => rs.map(r => r.dataset.deviceKey)")
        self.check(sorted(keys) == sorted(g["device_key"] for g in um["devices"]), f"[devices] unmapped rows {keys}")
        self.check("rogue-fw9" in keys, f"[devices] seeded unknown device missing: {keys}")
        # add a device (Plant A preselected)
        page.locator("[data-testid=dev-add-name]").fill("smoke-dev-01")
        page.locator("[data-testid=dev-add-btn]").click()
        page.wait_for_function("() => /mapped to/.test(document.querySelector('[data-testid=dev-add-msg]').textContent)", timeout=10000)
        page.wait_for_selector('[data-testid=dev-table] tr[data-device="smoke-dev-01"]', timeout=10000)
        # map the unknown device to Plant B -> replay
        b_id = self.site_id(req, "plant-b")
        row = page.locator('[data-testid=unmapped-table] tr[data-device-key="rogue-fw9"]')
        row.locator("select").select_option(str(b_id))
        row.locator("[data-testid=unmapped-map-rogue-fw9]").click()
        page.wait_for_function("() => /replayed 1 held line/.test(document.querySelector('[data-testid=unmapped-msg-rogue-fw9]').textContent)", timeout=10000)
        self.shot(page, "devices_mapped")
        page.wait_for_selector('[data-testid=unmapped-table] tr[data-device-key="rogue-fw9"]', state="detached", timeout=10000)
        mapped = [d for d in self.api(req, f"/site-devices?site_id={b_id}") if d["device_name"] == "rogue-fw9"]
        self.check(len(mapped) == 1 and mapped[0]["source"] == "manual", f"[devices] rogue-fw9 not mapped to Plant B: {mapped}")
        left = self.api(req, "/site-devices/unmapped")["pending_lines"] + self.api_all(req, "/site-devices/conflicts")["pending_conflicts"]
        page.wait_for_load_state("networkidle")
        self.check((badge.is_hidden() if not left else badge.inner_text() == str(left)), f"[devices] badge not updated (held {left})")

    def devices_conflicts(self, page, req, cf, badge):
        """B-11: the Conflicts list matches the API; resolve the seeded serial
        conflict as "Same device - replaced unit" through the in-page
        confirmation (keyboard: Escape cancels, Enter confirms) and check the
        replay, the registry serial and the badge."""
        rows = page.locator("[data-testid=conflicts-table] tbody tr")
        ids = rows.evaluate_all("rs => rs.map(r => r.dataset.conflict)")
        want = ["|".join([g["device_key"], g["kind"], g["serial"] or ""]) for g in cf["conflicts"]]
        self.check(sorted(ids) == sorted(want), f"[devices] conflict rows {ids} != API {want}")
        sc = "fgt-edge-a|serial_conflict|FGT60F0000009999"
        if not self.check(sc in ids, f"[devices] seeded serial conflict missing: {ids}"):
            return
        self.check(any(i.startswith("asa-fw01|site_mismatch|") for i in ids), f"[devices] seeded site mismatch missing: {ids}")
        mm = page.locator('[data-testid=conflict-row][data-kind="site_mismatch"]').first
        self.check(mm.locator("[data-testid=conflict-diff]").is_disabled(), "[devices] site mismatch offers 'Different device'")
        row = page.locator(f'[data-testid=conflict-row][data-conflict="{sc}"]')
        g = next(x for x in cf["conflicts"] if x["device_key"] == "fgt-edge-a")
        self.check(row.locator("[data-testid=conflict-line-serial]").inner_text().endswith("FGT60F0000009999")
                   and row.locator("[data-testid=conflict-reg-serial]").inner_text().endswith("FGT60F0000000001"),
                   "[devices] conflict serials not shown")
        self.check(row.locator("[data-testid=conflict-reg-site]").inner_text() == "Plant A", "[devices] registered site not shown")
        self.check(row.locator("[data-testid=conflict-count]").inner_text() == str(g["count"]), "[devices] conflict count")
        same = row.locator("[data-testid=conflict-same]")
        same.click()
        panel = row.locator("[data-testid=conflict-confirm]")
        self.check(panel.is_visible() and same.get_attribute("aria-expanded") == "true", "[devices] confirmation not opened")
        focused = page.evaluate("() => document.activeElement && document.activeElement.dataset.testid")
        self.check(focused == "conflict-confirm-btn", f"[devices] focus not on the confirm button ({focused})")
        page.keyboard.press("Escape")
        self.check(panel.is_hidden(), "[devices] Escape did not cancel the confirmation")
        focused = page.evaluate("() => document.activeElement && document.activeElement.dataset.testid")
        self.check(focused == "conflict-same", f"[devices] focus not returned to the action ({focused})")
        page.keyboard.press("Enter")                       # reopen from the keyboard
        self.check(panel.is_visible(), "[devices] Enter on the action did not open the confirmation")
        with page.expect_response(lambda r: "/site-devices/conflicts/resolve" in r.url) as ri:
            page.keyboard.press("Enter")                   # confirm (focused)
        body = ri.value.json()
        self.check(ri.value.status == 200 and body["replay"]["lines"] == g["count"], f"[devices] resolve failed: {ri.value.status} {body}")
        msg = row.locator("[data-testid=conflict-msg]")
        page.wait_for_function("(el) => /replayed \\d+ held line/.test(el.textContent)", arg=msg.element_handle(), timeout=10000)
        self.check(f"replayed {g['count']} held line" in msg.inner_text() and "Plant A" in msg.inner_text(), f"[devices] result summary {msg.inner_text()!r}")
        self.shot(page, "devices_conflict_resolved")
        page.wait_for_selector(f'[data-testid=conflict-row][data-conflict="{sc}"]', state="detached", timeout=10000)
        dev = [d for d in self.api_all(req, "/site-devices") if d["device_name"] == "fgt-edge-a"]
        self.check(len(dev) == 1 and dev[0]["serial"] == "FGT60F0000009999" and dev[0]["serial_source"] == "conflict_resolution",
                   f"[devices] registry serial not updated: {dev}")
        audit = self.api_all(req, "/site-devices/conflicts/resolutions")
        self.check(audit and audit[0]["action"] == "same_device" and audit[0]["target_site"] == "Plant A"
                   and audit[0]["events_created"] == body["replay"]["events_created"], f"[devices] resolution not recorded: {audit[:1]}")
        held = self.api(req, "/site-devices/unmapped")["pending_lines"] + self.api_all(req, "/site-devices/conflicts")["pending_conflicts"]
        page.wait_for_load_state("networkidle")
        self.check((badge.is_hidden() if not held else badge.inner_text() == str(held)), f"[devices] badge after resolve != {held}")

    def devices_ha(self, page, req):
        """B-12: the seeded a-p cluster FG-OT-PERIMETER-01 (Plant A) shows the
        HA badge (mode / group) and both member serials (source, last seen)
        as the API lists them; a third member is added through "Add member
        serial" and its in-row confirmation (Escape cancels and returns
        focus, Confirm posts) and then appears in the list and the API."""
        name = "fg-ot-perimeter-01"
        api_dev = [d for d in self.api(req, "/site-devices") if d["device_name"] == name]
        if not self.check(len(api_dev) == 1 and api_dev[0]["is_ha"], f"[devices] seeded HA cluster missing: {api_dev}"):
            return
        d = api_dev[0]
        row = page.locator(f'[data-testid=dev-table] tr[data-device="{name}"]')
        badge = row.locator("[data-testid=dev-ha-badge]")
        self.check(badge.is_visible() and "HA a-p" in badge.inner_text() and "OT-FW-HA" in badge.inner_text(),
                   f"[devices] HA badge {badge.inner_text() if badge.count() else None!r}")
        items = row.locator("[data-testid=dev-ha-member]")
        serials = items.evaluate_all("ls => ls.map(l => l.dataset.serial)")
        self.check(serials == [m["serial"] for m in d["members"]] and len(serials) == 2,
                   f"[devices] HA members {serials} != API {[m['serial'] for m in d['members']]}")
        srcs = row.locator("[data-testid=dev-ha-member-source]").all_inner_texts()
        self.check(any("HA event log" in t for t in srcs), f"[devices] member sources {srcs}")
        seen = row.locator("[data-testid=dev-ha-member-seen]").all_inner_texts()
        self.check(all(t.startswith("last seen") for t in seen), f"[devices] member last seen {seen}")
        new = "FGT60FHA00000003"
        inp = row.locator("[data-testid=dev-ha-add-serial]")
        inp.fill(new)
        inp.press("Enter")                                  # review -> confirmation step
        panel = row.locator("[data-testid=dev-ha-add-confirm]")
        self.check(panel.is_visible() and new in panel.inner_text() and "member 3 of 4" in panel.inner_text(),
                   f"[devices] add-member confirmation {panel.inner_text() if panel.is_visible() else 'hidden'!r}")
        focused = page.evaluate("() => document.activeElement && document.activeElement.dataset.testid")
        self.check(focused == "dev-ha-add-confirm-btn", f"[devices] focus not on the add confirm button ({focused})")
        page.keyboard.press("Escape")
        self.check(panel.is_hidden(), "[devices] Escape did not cancel the add-member confirmation")
        focused = page.evaluate("() => document.activeElement && document.activeElement.dataset.testid")
        self.check(focused == "dev-ha-add-btn", f"[devices] focus not returned to 'Add member serial' ({focused})")
        self.check(self.api(req, "/site-devices") and len(
            [m for x in self.api(req, "/site-devices") if x["id"] == d["id"] for m in x["members"]]) == 2,
            "[devices] cancelled add still changed the members")
        page.keyboard.press("Enter")                        # reopen from the keyboard
        with page.expect_response(lambda r: f"/site-devices/{d['id']}/serials" in r.url) as ri:
            row.locator("[data-testid=dev-ha-add-confirm-btn]").click()
        body = ri.value.json()
        self.check(ri.value.status == 201 and body["added"]["serial"] == new and body["added"]["source"] == "manual",
                   f"[devices] add member failed: {ri.value.status} {body}")
        msg = row.locator("[data-testid=dev-ha-add-msg]")
        self.check(f"Added {new}" in msg.inner_text(), f"[devices] add member message {msg.inner_text()!r}")
        page.wait_for_function(
            "(n) => document.querySelectorAll(`[data-testid=dev-table] tr[data-device='${n}'] [data-testid=dev-ha-member]`).length === 3",
            arg=name, timeout=10000)
        self.shot(page, "devices_ha_member_added")
        after = [x for x in self.api(req, "/site-devices") if x["id"] == d["id"]][0]
        self.check([m["serial"] for m in after["members"]][-1] == new and after["members"][-1]["source"] == "manual",
                   f"[devices] API members after add {after['members']}")

    def s_overview(self, page, req):
        """Phase 4: read-only roll-up page (cards match GET /sites/rollup)."""
        d = self.api(req, "/sites/rollup")
        cards = page.locator("[data-testid=ov-cards] .ov-card")
        self.check(cards.count() == len(d["sites"]), f"[overview] cards {cards.count()} != sites {len(d['sites'])}")
        codes = cards.evaluate_all("cs => cs.map(c => c.dataset.code)")
        self.check(sorted(codes) == sorted(x["code"] for x in d["sites"]), f"[overview] codes {codes}")
        for x in d["sites"]:
            card = page.locator(f'.ov-card[data-code="{x["code"]}"]')
            self.check(card.locator("[data-testid=ov-open-count]").inner_text() == f'{x["open_findings"]} open', f"[overview] {x['code']} open count")
            self.check(x["attestation"]["state"] in card.locator("[data-testid=ov-att]").inner_text(), f"[overview] {x['code']} attestation text")
            href = card.locator(f"[data-testid=ov-pdf-{x['code']}]").get_attribute("href") or ""
            self.check(href.endswith(f"/reports/compliance.pdf?site_id={x['id']}"), f"[overview] pdf link {href}")
        # per-site PDF link serves a PDF for that site only
        b = next(x for x in d["sites"] if x["code"] == "plant-b")
        r = req.get(self.base + f"/reports/compliance.pdf?site_id={b['id']}")
        self.check(r.ok and r.body()[:4] == b"%PDF", "[overview] per-site PDF not served")
        # click-through selects the site and opens its findings
        page.locator("[data-testid=ov-open-plant-b]").click()
        page.wait_for_selector("#page-findings.active", timeout=10000)
        self.check(page.locator("#site-select").input_value() == str(b["id"]), "[overview] click-through did not select Plant B")
        page.wait_for_load_state("networkidle")
        # restore Plant A for the sections that follow
        a_id = self.site_id(req, "plant-a")
        page.locator("#site-select").select_option(str(a_id))
        page.wait_for_load_state("networkidle")
        self.goto(page, "overview")

    def findings_asset_drawer(self, page, req):
        """Owner 2026-10-14: a finding about a host opens the asset in a side drawer (inventory
        fields, Classify and the host's findings, editable there); the record keeps the focus and
        Escape returns it to the finding."""
        f = next((x for x in self.api(req, "/findings?check_name=unknown_device&status=open&limit=50")
                  if (x.get("detail") or {}).get("ip")), None)
        if not self.check(f is not None, "[findings] seed has no unknown_device finding with an address"):
            return
        page.locator("#f-search").fill(f["detail"]["ip"])
        page.wait_for_function("(id) => !!document.querySelector(`.finding-row[data-finding-id=\"${id}\"]`)", arg=f["id"], timeout=15000)
        row = page.locator(f'.finding-row[data-finding-id="{f["id"]}"]')
        if not self.check(row.count() == 1, "[findings] unknown_device row not listed"):
            return
        row.click()
        btn = page.locator("[data-testid=finding-edit-asset]").first
        if not self.check(btn.count() == 1, "[findings] no Edit asset button"):
            return
        btn.click()
        page.wait_for_selector("[data-testid=asset-drawer] [data-testid=linked-finding]", timeout=15000)
        drawer = page.locator("[data-testid=asset-drawer]")
        self.check(drawer.locator("#ae-save").count() == 1 and drawer.locator("[data-testid=classify-box]").count() == 1,
                   "[findings] drawer lacks the inventory fields / Classify")
        self.check(drawer.locator(f'[data-testid=linked-finding][data-finding-id="{f["id"]}"]').count() == 1,
                   "[findings] the finding is not listed in the asset drawer")
        self.check(page.evaluate("() => document.getElementById('asset-drawer').contains(document.activeElement)"),
                   "[findings] focus not in the drawer")
        page.keyboard.press("Escape")
        self.check(drawer.is_hidden(), "[findings] Escape did not close the drawer")
        self.check(page.evaluate("() => document.activeElement && document.activeElement.dataset.testid === 'finding-edit-asset'"),
                   "[findings] focus not returned to the Edit asset button")
        page.locator("#f-search").fill("")
        page.wait_for_load_state("networkidle")

    def findings_excluded_toggle(self, page, req):
        """Owner 2026-10-14: findings of a check left out of the report are hidden; the toggle
        lists them, marked."""
        f = next((x for x in self.api(req, "/findings?status=open&limit=50") if x.get("check_name")), None)
        if not self.check(f is not None, "[findings] no open finding to exclude"):
            return
        n0 = int(self.api(req, "/findings/summary")["total_open"])
        req.put(self.base + f"/reports/check-selection?site_id={self.cur_site}", data={"exclude": [f["check_name"]], "by": "smoke"})
        page.locator("#findings-reload").click() if page.locator("#findings-reload").count() else page.evaluate("() => loadFindings()")
        page.wait_for_load_state("networkidle")
        n1 = int(self.api(req, "/findings/summary")["total_open"])
        self.check(n1 < n0 and page.locator(f'.finding-row[data-finding-id="{f["id"]}"]').count() == 0,
                   f"[findings] excluded check still listed / counted ({n0} -> {n1})")
        page.locator("[data-testid=findings-show-excluded]").check()
        page.wait_for_load_state("networkidle")
        page.wait_for_selector(f'.finding-row[data-finding-id="{f["id"]}"] [data-testid=finding-excluded]', timeout=15000)
        page.locator("[data-testid=findings-show-excluded]").uncheck()
        req.put(self.base + f"/reports/check-selection?site_id={self.cur_site}", data={"include": [f["check_name"]]})
        page.wait_for_load_state("networkidle")
        self.check(int(self.api(req, "/findings/summary")["total_open"]) == n0, "[findings] count not restored after re-including")

    def s_findings(self, page, req):
        summary = self.api(req, "/findings/summary")
        for st in ("open", "acknowledged", "closed"):
            txt = page.locator(f'#findings-summary .st-card[data-status="{st}"] .summary-count').inner_text()
            self.check(int(txt) == summary["by_status"].get(st, 0), f"[findings] {st} card {txt} != by_status {summary['by_status'].get(st, 0)}")
        self.check(summary["by_status"].get("open", 0) == summary["total_open"], "[findings] by_status.open != total_open")
        self.findings_asset_drawer(page, req)
        self.findings_config_snippet(page, req)
        self.findings_excluded_toggle(page, req)
        self.findings_paging(page, req)
        for sev, n in summary["by_severity"].items():
            txt = page.locator(f"#findings-summary .sev-{sev} .summary-count").inner_text()
            self.check(int(txt) == n, f"[findings] {sev} count {txt} != {n}")
        rows = page.locator(".finding-row").count()
        self.check(rows > 0, "[findings] list empty")
        # close one open finding, then check the closed styling
        page.locator("#f-status").select_option("open")
        page.wait_for_load_state("networkidle")
        page.locator(".finding-row").first.click()
        # "Why this was flagged" (app/explain.py): a pop-up from the row's "?"
        # button, not part of the panel
        self.check(page.locator("#findings-side [data-testid=finding-why]").count() == 0,
                   "[findings] explanation should not take panel space")
        page.locator(".finding-row.selected [data-testid=finding-why-btn]").click()
        page.wait_for_selector("[data-testid=why-dialog] [data-testid=finding-why] .why-sec", timeout=30000)
        # owner 2026-10-17: standard references and, for FortiGate config checks, a FortiOS example
        self.check(page.locator("[data-testid=why-dialog] [data-testid=finding-why-refs] li").count() >= 1, "[findings] no standard references in the explanation")
        secs = page.locator("[data-testid=why-dialog] .why-sec h5").all_inner_texts()
        self.check({"WHAT WAS FOUND", "WHY IT IS AN ISSUE", "WHY THIS SEVERITY", "HOW TO RESOLVE",
                    "HOW IT CLOSES"} <= {x.strip().upper() for x in secs},
                   f"[findings] explanation sections missing: {secs}")
        page.locator("[data-testid=why-dialog-close]").click()
        self.check(not page.locator("[data-testid=why-dialog]").evaluate("d => d.open"),
                   "[findings] explanation pop-up did not close")
        page.locator("#f-edit-status").select_option("closed")
        page.locator("#f-edit-notes").fill("closed by smoke test")
        page.locator("#findings-side button.primary").click()
        page.wait_for_function("() => /Saved/.test(document.getElementById('f-save-msg')?.textContent || '')", timeout=10000)
        page.locator("#f-status").select_option("closed")
        page.wait_for_load_state("networkidle")
        page.wait_for_selector(".finding-row.st-closed", timeout=10000)
        op = page.evaluate("() => getComputedStyle(document.querySelector('.finding-row.st-closed')).opacity")
        self.check(float(op) < 1, "[findings] closed finding not styled distinctly")
        after = self.api(req, "/findings/summary")
        self.check(after["total_open"] == summary["total_open"] - 1, "[findings] closing did not reduce open count")
        txt = page.locator('#findings-summary .st-card[data-status="closed"] .summary-count').inner_text()
        self.check(int(txt) == after["by_status"].get("closed", 0), "[findings] closed card not refreshed after save")
        page.locator("#f-status").select_option("")
        page.wait_for_load_state("networkidle")
        self.findings_false_positive(page, req)
        self.findings_sl_fr(page, req)
        self.findings_seen_and_reviews(page, req)

    def findings_false_positive(self, page, req):
        """SF: mark an open finding a false positive (reason required); the
        badge, the panel and the status counts follow; it sorts last."""
        page.locator("#f-status").select_option("open")
        page.wait_for_load_state("networkidle")
        page.wait_for_function("() => document.querySelectorAll('.finding-row').length && !document.querySelector('.finding-row:not(.st-open)')", timeout=15000)
        page.locator(".finding-row.st-open").first.click()
        page.wait_for_selector("#f-edit-status", timeout=15000)
        page.locator("#f-edit-status").select_option("false_positive")
        self.check(page.locator("#f-edit-reason").is_visible(), "[findings] reason box hidden for a false positive")
        page.locator("#f-edit-ack").fill("smoke")
        page.locator("#findings-side button.primary").click()
        page.wait_for_function("() => /reason/.test(document.getElementById('f-save-msg')?.textContent || '')", timeout=10000)
        page.locator("#f-edit-reason").fill("smoke: design conduit")
        page.locator("#findings-side button.primary").click()
        page.wait_for_function("() => /Saved/.test(document.getElementById('f-save-msg')?.textContent || '')", timeout=10000)
        page.locator("#f-status").select_option("false_positive")
        page.wait_for_load_state("networkidle")
        page.wait_for_selector(".finding-row.st-false_positive", timeout=10000)
        page.locator(".finding-row.st-false_positive").first.click()
        side = page.locator("#findings-side [data-testid=finding-fp]").inner_text()
        self.check("smoke: design conduit" in side and "smoke," in side.lower(), f"[findings] false-positive panel: {side[:120]}")
        s = self.api(req, "/findings/summary")
        txt = page.locator('#findings-summary .st-card[data-status="false_positive"] .summary-count').inner_text()
        self.check(int(txt) == s["by_status"].get("false_positive", 0) >= 1, "[findings] false-positive card count")
        page.locator("#f-status").select_option("")
        page.wait_for_load_state("networkidle")
        sts = page.locator(".finding-row .status-badge").all_inner_texts()
        fp_idx = [i for i, t in enumerate(sts) if t == "False positive"]
        self.check(fp_idx and fp_idx[0] >= len(sts) - len(fp_idx), f"[findings] false positives not last: {fp_idx[:3]} of {len(sts)}")

    def findings_sl_fr(self, page, req):
        """Target SL / FR filters (app/security_levels.py): the list and its
        count follow GET /findings?target_sl= / ?fr=, SL badges stay <= target."""
        sel = page.locator("#site-select").input_value()
        site_q = f"&site_id={sel}" if sel else ""
        for sel_id, param, val in (("#f-sl", "target_sl", "1"), ("#f-fr", "fr", "FR5")):
            page.locator(sel_id).select_option(val)
            page.wait_for_load_state("networkidle")
            r = req.get(self.base + f"/findings?limit=1&{param}={val}{site_q}")
            total = int(r.headers.get("x-total-count", "-1"))
            page.wait_for_function(
                "n => (document.getElementById('findings-status')?.textContent || '').startsWith(n + ' matching')",
                arg=str(total), timeout=10000)
            if param == "target_sl":
                badges = page.locator(".finding-row [data-testid=finding-sl]").all_inner_texts()
                self.check(all(b == "SL1" for b in badges), f"[findings] SL filter shows {set(badges)}")
            page.locator(sel_id).select_option("")
            page.wait_for_load_state("networkidle")
        page.locator("#f-group").select_option("security_level")
        heads = page.locator("#findings-list-wrap .group-header > span:first-child").all_inner_texts()
        # the group header is CSS-uppercased, and inner_text returns the rendered text
        self.check(heads and all(h.upper().startswith("SL") or h.upper().startswith("(NO 62443") for h in heads),
                   f"[findings] security-level groups: {heads}")
        page.locator("#f-group").select_option("none")
        self.check(page.locator("#rep-sl option").count() == 5, "[report] target SL select missing")

    def findings_seen_and_reviews(self, page, req):
        """F-04/F-17: last seen + occurrences in list and detail; Run reviews now."""
        page.wait_for_function("() => /^1–/.test(document.getElementById('f-range').textContent)", timeout=10000)
        size = int(page.locator("#f-limit").input_value())
        sel = page.locator("#site-select").input_value()
        site_q = f"&site_id={sel}" if sel else ""   # compare against the site the UI shows
        rows = req.get(self.base + f"/findings?limit={size}&offset=0{site_q}").json()
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sevs = page.locator(".finding-row:not(.st-false_positive) .badge").all_inner_texts()   # false positives sort last
        self.check([rank.get(x, 5) for x in sevs] == sorted(rank.get(x, 5) for x in sevs),
                   f"[findings] list not in severity order: {sevs[:12]}")
        got = page.locator(".finding-row .finding-time").evaluate_all("es => es.map(e => e.dataset.lastSeen || '')")
        self.check(got == [f.get("last_seen") or "" for f in rows], "[findings] last_seen per row differs from the API")
        occ = page.locator(".finding-row .occ-badge").count()
        self.check(occ == sum(1 for f in rows if (f.get("occurrence_count") or 1) > 1), "[findings] occurrence badges != rows with occurrence_count > 1")
        if "last_seen" not in rows[0]:
            print("  NOTE: GET /findings rows carry no last_seen / occurrence_count yet - UI shows '—'")
        page.locator(".finding-row").first.click()
        side = page.locator("#findings-side").inner_text()
        self.check("LAST SEEN" in side.upper() and "OCCURRENCES" in side.upper(), "[findings] detail lacks Last seen / Occurrences")
        with page.expect_response(lambda r: "/reviews/run" in r.url and r.request.method == "POST", timeout=120000) as ri:
            page.locator("#findings-run-reviews").click()
        r = ri.value.json()
        page.wait_for_selector("#findings-run-result [data-testid=review-run]", timeout=30000)
        box = page.locator("#findings-run-result")
        auto_total = sum(r["auto_resolved"].values())
        for k, want in (("total_findings", r["total_findings"]), ("failed_reviews", len(r["failed_reviews"])),
                        ("escalations", r["escalations"]), ("auto_resolved", auto_total), ("reviews", len(r["by_review"]))):
            got = box.locator(f'[data-stat="{k}"] b').inner_text()
            self.check(got == str(want), f"[findings] review run {k}: shown {got} != {want}")
        for name, n in r["auto_resolved"].items():
            cells = box.locator(f'tr[data-review="{name}"] td').all_inner_texts()
            self.check(len(cells) >= 3 and cells[2] == str(n), f"[findings] auto-resolved for {name}: {cells}")
        listed = box.locator("tbody tr").count()
        exp = len({n for n, c in r["by_review"].items() if c} | {n for n, c in r["auto_resolved"].items() if c} | set(r["failed_reviews"]))
        self.check(listed == exp, f"[findings] review table rows {listed} != {exp}")
        page.wait_for_load_state("networkidle")
        summary = self.api(req, "/findings/summary")
        want = summary["by_status"].get("open", 0)
        try:   # the list reload after the run can outlast networkidle on a busy host
            page.wait_for_function(
                """(n) => { const e = document.querySelector('#findings-summary .st-card[data-status="open"] .summary-count');
                           return e && Number(e.textContent) === n; }""", arg=want, timeout=15000)
        except Exception:  # noqa: BLE001 - reported by the check below
            pass
        txt = page.locator('#findings-summary .st-card[data-status="open"] .summary-count').inner_text()
        self.check(int(txt) == want, f"[findings] counts not refreshed after review run ({txt} != {want})")

    def wait_range(self, page, text):
        try:
            page.wait_for_function("(t) => document.getElementById('f-range').textContent === t", arg=text, timeout=10000)
        except Exception:  # noqa: BLE001
            self.check(False, f"[findings] range {page.locator('#f-range').inner_text()!r} != {text!r}")

    def findings_paging(self, page, req):
        page.locator("#f-status").select_option("")
        page.locator("#f-limit").select_option("50")
        page.wait_for_load_state("networkidle")
        r = req.get(self.base + "/findings?limit=50&offset=0")
        total = int(r.headers["x-total-count"])
        self.check(total > 50, f"[findings] seed too small to page ({total})")
        self.wait_range(page, f"1–50 of {total}")
        self.check(page.locator(".finding-row").count() == 50, "[findings] page 1 row count != 50")
        # owner 2026-10-12: Prev / Next move the selection one finding; at the edge of the
        # page they load the neighbouring page (first / last finding selected)
        rows = page.locator("#findings-list-wrap .finding-row")
        rows.first.click()
        self.check(page.locator("#f-prev").is_disabled(), "[findings] prev enabled on the first finding")
        self.check("finding 1 of" in page.locator("#f-pos").inner_text(), "[findings] position not shown")
        page.locator("#f-next").click()
        self.check(rows.nth(1).get_attribute("aria-pressed") == "true" and page.locator("#f-range").inner_text().startswith("1–"),
                   "[findings] Next did not select the next finding on the page")
        # clicking a row deep in the list keeps it in place (no jump to the top)
        deep = rows.nth(40)
        deep.scroll_into_view_if_needed()
        y0 = deep.bounding_box()["y"]
        deep.click()
        self.check(abs(deep.bounding_box()["y"] - y0) < 2 and deep.get_attribute("aria-pressed") == "true",
                   "[findings] the clicked finding moved")
        rows.last.click()
        page.locator("#f-next").click()
        page.wait_for_load_state("networkidle")
        page.wait_for_function("() => /^51–/.test(document.getElementById('f-range').textContent)", timeout=10000)
        self.check(page.locator("#findings-list-wrap .finding-row").first.get_attribute("aria-pressed") == "true",
                   "[findings] Next across the page did not select the first finding of page 2")
        exp = [f["title"] for f in req.get(self.base + "/findings?limit=50&offset=50").json()]
        got = page.locator(".finding-row .finding-title").all_inner_texts()
        self.check(got == exp, "[findings] page 2 rows differ from GET /findings?offset=50")
        self.check(page.locator("#f-range").inner_text() == f"51–{min(100, total)} of {total}", "[findings] page 2 range wrong")
        if total <= 100:
            page.locator("#findings-list-wrap .finding-row").last.click()
            self.check(page.locator("#f-next").is_disabled(), "[findings] next enabled on the last finding")
        page.locator("#findings-list-wrap .finding-row").first.click()
        page.locator("#f-prev").click()
        page.wait_for_function("() => /^1–/.test(document.getElementById('f-range').textContent)", timeout=10000)
        self.check(page.locator("#findings-list-wrap .finding-row").last.get_attribute("aria-pressed") == "true",
                   "[findings] Prev across the page did not select the last finding of page 1")
        # server-side filter resets to page 1 and N follows the filter
        page.locator("#f-status").select_option("open")
        page.wait_for_load_state("networkidle")
        n_open = int(req.get(self.base + "/findings?status=open&limit=1").headers["x-total-count"])
        self.wait_range(page, f"1–50 of {n_open}" if n_open >= 50 else f"1–{n_open} of {n_open}")
        self.check(req.get(self.base + "/findings?limit=0").status == 422, "[findings] limit=0 not rejected")
        page.locator("#f-status").select_option("")
        page.wait_for_load_state("networkidle")
        self.wait_range(page, f"1–50 of {total}")
        self.findings_search(page, req, total)
        page.locator("#f-limit").select_option("100")
        page.wait_for_load_state("networkidle")

    def findings_search(self, page, req, total):
        """N-12: the search box queries the server (q=), across all pages."""
        late = req.get(self.base + "/findings?limit=50&offset=50").json()
        cands = [f["check_name"] for f in late if f.get("check_name")]
        if not cands:
            self.check(False, "[findings] no check_name on page 2 to search for")
            return
        q = cands[-1].upper()           # case-insensitive, and only on page 2+ of the unfiltered list
        r = req.get(self.base + "/findings?" + urllib.parse.urlencode({"q": q, "limit": 50}))
        n = int(r.headers["x-total-count"])
        exp = [f["title"] for f in r.json()]
        page.locator("#f-search").fill(q)
        self.wait_range(page, f"1–{min(n, 50)} of {n}")
        got = page.locator(".finding-row .finding-title").all_inner_texts()
        self.check(got == exp, f"[findings] search {q!r}: rows differ from GET /findings?q=")
        page.locator("#f-search").fill("zz-no-such-finding-zz")
        self.wait_range(page, "0–0 of 0")
        self.check("zz-no-such-finding-zz" in page.locator("#findings-list-wrap").inner_text(), "[findings] empty search state missing")
        page.locator("#f-search").fill("")
        self.wait_range(page, f"1–50 of {total}")

    def s_topology(self, page, req):
        t = self.api(req, "/topology")
        # one card per device: the addresses of a MAC share a card (data-node-ids)
        shown = page.locator(".host-node").evaluate_all("ns => ns.flatMap(n => (n.dataset.nodeIds || n.dataset.nodeId).split(' '))")
        self.check(sorted(shown) == sorted(str(n["id"]) for n in t["nodes"]), "[topology] node count mismatch")
        self.check(page.locator(".fw-boundary-chip").count() == len(t["firewall_boundaries"]), "[topology] boundary chips mismatch")
        if t["edges"]:
            src = t["edges"][0]["source"]
            page.locator(f'.host-node[data-node-ids~="{src}"]').click()
            self.check(page.locator("#topo-panel-body .conn-item").count() >= 1, "[topology] selected host shows no sessions")
            # Classify control: suggestions + type / level form for the selected host
            page.wait_for_selector("#topo-panel-body [data-testid=classify-box] [data-testid=cls-save]", timeout=10000)
            self.check(page.locator("#topo-panel-body [data-testid=cls-type] option").count() > 10,
                       "[topology] classify: device type list empty")
            # owner 2026-10-13: DNS / NTP server choices under L3 and L4
            groups = page.locator("#topo-panel-body [data-testid=cls-type] optgroup").evaluate_all(
                "gs => Object.fromEntries(gs.map(g => [g.label, [...g.children].map(o => o.value)]))")
            for lvl, keys in (("L3 ", ("site_dns_server", "site_ntp_server")), ("L4 ", ("enterprise_dns_server", "enterprise_ntp_server"))):
                vals = next((v for k, v in groups.items() if k.startswith(lvl)), [])
                self.check(all(k in vals for k in keys), f"[topology] classify: {keys} not under {lvl.strip()}: {vals}")
        # owner 2026-10-13: drag a host card to another level lane (confirm bar), then
        # drag it to Unclassified to return it to automatic classification
        mover = page.locator('.level-band[data-lane="u"] .host-node[draggable="true"]').first
        if mover.count() and page.locator('.level-band[data-lane="3"]').count():
            mid = mover.get_attribute("data-node-id")
            mover.drag_to(page.locator('.level-band[data-lane="3"] .level-label'))
            self.check(page.locator("[data-testid=topo-move]").is_visible()
                       and "L3" in page.locator("[data-testid=topo-move-text]").inner_text(), "[topology] drag: no confirmation bar")
            with page.expect_response(lambda r: f"/hosts/{mid}/classification" in r.url and r.request.method == "PATCH"):
                page.locator("[data-testid=topo-move-ok]").click()
            page.wait_for_load_state("networkidle")
            self.check(page.locator(f'.level-band[data-lane="3"] .host-node[data-node-id="{mid}"]').count() == 1,
                       "[topology] drag: host not drawn in L3 after the move")
            # an empty L5 lane is drawn hidden and shown during a drag (every level is a target)
            if page.locator('.level-band.lane-optional[data-lane="5"]').count():
                l3card = page.locator(f'.level-band[data-lane="3"] .host-node[data-node-id="{mid}"]')
                l3card.hover()
                page.mouse.down()
                page.mouse.move(5, 5, steps=5)
                self.check(page.locator('.level-band[data-lane="5"]').is_visible(), "[topology] drag: empty L5 lane not shown while dragging")
                page.mouse.up()
                if page.locator("[data-testid=topo-move-cancel]").is_visible():
                    page.locator("[data-testid=topo-move-cancel]").click()
                self.check(page.locator('.level-band[data-lane="5"]').is_hidden(), "[topology] drag: empty L5 lane still shown after the drag")
            page.locator(f'.level-band[data-lane="3"] .host-node[data-node-id="{mid}"]').drag_to(
                page.locator('.level-band[data-lane="u"] .level-label'))
            # owner 2026-10-13: Unclassified offers "Leave unclassified" (pin) and, for a
            # hand-set host, "Return to automatic"
            self.check("unclassified" in page.locator("[data-testid=topo-move-text]").inner_text()
                       and page.locator("[data-testid=topo-move-auto]").is_visible(), "[topology] drag back: no unclassified / automatic offer")
            with page.expect_response(lambda r: f"/hosts/{mid}/classification" in r.url and r.request.method == "DELETE"):
                page.locator("[data-testid=topo-move-auto]").click()
            page.wait_for_load_state("networkidle")
        # owner 2026-10-13: a multi-homed device (one MAC, two subnets) is one red card per
        # address, joined by a "DMZ bypass" link; dragging one card moves only that address
        arp = "? (10.100.159.38) at 28:cf:e9:18:b5:ed [ether] on eth0\n? (192.168.88.52) at 28:cf:e9:18:b5:ed [ether] on eth1\n"
        r = req.post(self.base + f"/ingest/arp?site={self.cur_site}&format_hint=unix",
                     multipart={"file": {"name": "mh.txt", "mimeType": "text/plain", "buffer": arp.encode()}})
        if self.check(r.ok, f"[topology] multi-homed seed upload failed ({r.status})"):
            ids = {h["ip"]: h["id"] for h in self.api(req, "/hosts?limit=5000") if h["ip"] in ("10.100.159.38", "192.168.88.52")}
            req.patch(self.base + f"/hosts/{ids['10.100.159.38']}/classification?purdue_level=4")
            req.patch(self.base + f"/hosts/{ids['192.168.88.52']}/classification?purdue_level=2")
            page.locator("#topo-reload").click()
            page.wait_for_load_state("networkidle")
            mh = page.locator(".host-node.multi-homed")
            self.check(mh.count() == 2 and page.locator('.level-band[data-lane="4"] .host-node.multi-homed').count() == 1
                       and page.locator('.level-band[data-lane="2"] .host-node.multi-homed').count() == 1,
                       f"[topology] multi-homed: expected one red card in L4 and one in L2, got {mh.count()}")
            self.check("same device as 10.100.159.38 (L4)" in page.locator(f'.host-node[data-node-id="{ids["192.168.88.52"]}"]').inner_text(),
                       "[topology] multi-homed: peer badge missing")
            self.check(page.evaluate("() => mhLinkLabel(topoById.get(%d), topoById.get(%d))" % (ids["10.100.159.38"], ids["192.168.88.52"])) == "DMZ bypass",
                       "[topology] multi-homed: link not labelled DMZ bypass")
            page.locator(f'.host-node[data-node-id="{ids["192.168.88.52"]}"]').drag_to(page.locator('.level-band[data-lane="3"] .level-label'))
            self.check("Only this address moves" in page.locator("[data-testid=topo-move-text]").inner_text(), "[topology] multi-homed: drag text")
            with page.expect_response(lambda r: f"/hosts/{ids['192.168.88.52']}/classification" in r.url and "apply_to_same_mac" not in r.url):
                page.locator("[data-testid=topo-move-ok]").click()
            page.wait_for_load_state("networkidle")
            lv = {h["ip"]: h["purdue_level"] for h in self.api(req, "/hosts?limit=5000") if h["ip"] in ids}
            self.check(lv == {"10.100.159.38": 4, "192.168.88.52": 3}, f"[topology] multi-homed: drag moved the other address too: {lv}")
        # a flat capture segment "A/24 + B/24" holding both subnets must not merge the
        # device's addresses into one card (each address keyed by its own subnet)
        seg_keys = page.evaluate("""() => { const seg = '192.168.88.0/24 + 10.100.159.0/24';
            const a = {id: -1, ip: '10.100.159.38', mac: 'aa:00:00:00:00:01', segment: seg};
            const b = {id: -2, ip: '192.168.88.52', mac: 'aa:00:00:00:00:01', segment: seg};
            return [topoSubnetKey(a), topoSubnetKey(b), topoMultiHomed([a, b]).size]; }""")
        self.check(seg_keys == ["10.100.159.0/24", "192.168.88.0/24", 1], f"[topology] multi-homed on a shared segment: {seg_keys}")
        self.check(page.locator("#topo-trunc").is_hidden() == (not t.get("truncated")), "[topology] truncation notice state wrong")
        # F-09: stale badge + address history in node detail
        # (G5: outside addresses share the one Internet card - inside hosts only)
        node_ids = {n["id"] for n in t["nodes"] if not n.get("external")}
        stale = [h for h in self.api(req, "/hosts") if h["stale"] and h["id"] in node_ids]
        self.check(all(page.locator('.host-node.stale[data-node-ids~="%s"]' % h["id"]).count() == 1 for h in stale)
                   and page.locator(".host-node.stale").count() <= len(stale), "[topology] stale node count != /hosts stale")
        if self.check(stale, "[topology] seed has no stale host"):
            hid = stale[0]["id"]
            page.locator(f'.host-node[data-node-ids~="{hid}"]').click()
            self.check(page.locator("#topo-panel-body [data-testid=stale-badge]").count() >= 1, "[topology] stale badge missing in node detail")
            hist = self.api(req, f"/hosts/{hid}/history")["history"]
            page.wait_for_selector("#topo-panel-body .host-history .detail-label:has-text('Address history (')", timeout=10000)
            self.check(page.locator("#topo-panel-body .host-history [data-history-id]").count() == min(len(hist), 40), "[topology] history rows != API")
        # a non-stale host with a multi-entry history
        for n in t["nodes"][:30]:
            hist = self.api(req, f"/hosts/{n['id']}/history")["history"]
            if len(hist) > 1:
                page.locator(f'.host-node[data-node-ids~="{n["id"]}"]').click()
                page.wait_for_selector("#topo-panel-body .host-history [data-history-id]", timeout=10000)
                ips = page.locator("#topo-panel-body .host-history [data-history-id] .mono").all_inner_texts()
                self.check(any(h["mac"] in ips for h in hist if h["mac"]), "[topology] history MACs not shown")
                break
        # N-16: a capped /topology response must show a notice with the totals
        pat = re.compile(r"/topology(\?site_id=\d+)?$")

        def fake(route):
            resp = route.fetch()
            body = resp.json()
            body.update(truncated=True, hosts_total=len(body["nodes"]) + 12345,
                        sessions_total=len(body["edges"]) + 678)
            route.fulfill(response=resp, json=body)
        page.route(pat, fake)
        page.locator("#topo-reload").click()
        try:
            page.wait_for_selector("#topo-trunc:not([hidden])", timeout=10000)
            txt = page.locator("#topo-trunc").inner_text()
            self.check(f"{len(t['nodes']) + 12345:,}" in txt and f"{len(t['edges']) + 678:,}" in txt,
                       f"[topology] truncation notice lacks totals: {txt!r}")
        except Exception:  # noqa: BLE001
            self.check(False, "[topology] truncation notice not shown for truncated=true")
        page.unroute(pat)
        page.locator("#topo-reload").click()
        try:
            page.wait_for_selector("#topo-trunc", state="hidden", timeout=10000)
        except Exception:  # noqa: BLE001
            self.check(False, "[topology] truncation notice not cleared on reload")

    def fw_config(self, page, req, devs):
        """Owner 2026-10-14: the device card's *Config* opens the stored (masked) config in the
        drawer - line numbers, folding sections, find, go to line, download."""
        with_fw = [d for d in devs if d.get("firewall_id") is not None]
        if not self.check(with_fw, "[fw_config] no device with a firewall id"):
            return
        d = with_fw[0]
        meta = self.api(req, f"/firewalls/{d['firewall_id']}/config")
        btn = page.locator(f'.fw-device-card[data-device-id="{d["id"]}"] [data-testid=fw-config-button]')
        if not self.check(btn.count() == 1, "[fw_config] no Config button on the card"):
            return
        btn.click()
        page.wait_for_selector("[data-testid=asset-drawer] [data-testid=cfg-view]", timeout=15000)
        drawer = page.locator("[data-testid=asset-drawer]")
        n = drawer.locator("[data-testid=cfg-line]").count()
        self.check(n == meta["line_count"], f"[fw_config] {n} lines shown, API says {meta['line_count']}")
        self.check("ENC " not in drawer.locator("[data-testid=cfg-view]").inner_text() or "ENC ***" in drawer.locator("[data-testid=cfg-view]").inner_text(),
                   "[fw_config] an ENC value is shown unmasked")
        drawer.locator("[data-testid=cfg-search]").fill("config firewall policy")
        page.wait_for_function("() => /\\d+ \\/ \\d+|no match/.test(document.querySelector('[data-testid=cfg-matches]')?.textContent || '')", timeout=5000)
        self.check(drawer.locator("[data-testid=cfg-line].hit").count() >= 1, "[fw_config] find marked no line")
        self.check(drawer.locator("[data-testid=cfg-line].focus").count() == 1, "[fw_config] find did not focus the first match")
        drawer.locator("[data-testid=cfg-jump]").fill("1")
        drawer.locator("[data-testid=cfg-jump]").press("Enter")
        self.check(drawer.locator('[data-testid=cfg-line][data-line="1"]').evaluate("n => n.classList.contains('focus')"), "[fw_config] go to line 1 did not focus it")
        href = drawer.locator("[data-testid=cfg-download]").get_attribute("href") or ""
        self.check("download=true" in href, "[fw_config] download link missing")
        self.shot(page, "fw_config")
        page.keyboard.press("Escape")
        self.check(drawer.is_hidden(), "[fw_config] Escape did not close the drawer")

    def findings_config_snippet(self, page, req):
        """Owner 2026-10-14: a config_* finding shows the config lines behind it; *Open in config*
        opens the drawer on those lines."""
        rows = self.api(req, "/findings?check_name=config_insecure_mgmt_protocol&limit=5") or \
            self.api(req, "/findings?category=config_review&limit=5")
        if not self.check(rows, "[findings_config] seed has no config finding"):
            return
        f = rows[0]
        page.locator("#f-search").fill(f["title"][:40])
        page.wait_for_function("(id) => !!document.querySelector(`.finding-row[data-finding-id=\"${id}\"]`)", arg=f["id"], timeout=15000)
        page.locator(f'.finding-row[data-finding-id="{f["id"]}"]').click()
        det = page.locator("[data-testid=finding-config]")
        if not self.check(det.count() == 1, "[findings_config] no Configuration lines block"):
            return
        det.locator("summary").click()
        page.wait_for_selector("[data-testid=cfg-snippet], [data-testid=cfg-snippet-none]", timeout=15000)
        if self.check(det.locator("[data-testid=cfg-snippet]").count() == 1, "[findings_config] no snippet for the config finding"):
            first = det.locator("[data-testid=cfg-snippet-line]").first.inner_text()
            self.check("edit" in first or "config" in first, f"[findings_config] snippet does not start at a block: {first!r}")
            det.locator("[data-testid=cfg-open]").click()
            page.wait_for_selector("[data-testid=asset-drawer] [data-testid=cfg-view]", timeout=15000)
            self.check(page.locator("[data-testid=asset-drawer] [data-testid=cfg-line].focus").count() == 1, "[findings_config] Open in config did not focus the line")
            self.shot(page, "findings_config")
            page.keyboard.press("Escape")
        page.locator("#f-search").fill("")
        page.wait_for_load_state("networkidle")

    def s_nettopo(self, page, req):
        """Owner 2026-10-16: Network Topology - lanes by subnet / VLAN with function-coloured hosts,
        separators between lanes, the asset drawer from a card, Declare… on a lane."""
        j = self.api(req, "/topology/subnets")
        page.wait_for_selector("[data-testid=nt-lane]", timeout=15000)
        self.check(page.locator("[data-testid=nt-lane]").count() == len(j["lanes"]), "[nettopo] lane count mismatch")
        self.check(page.locator("[data-testid=nt-host]").count() == j["hosts_total"], "[nettopo] host card count mismatch")
        self.check(page.locator("[data-testid=nt-sep]").count() == len(j["separators"]), "[nettopo] separator count mismatch")
        fns = {page.locator("[data-testid=nt-host]").nth(i).get_attribute("data-fn") for i in range(min(50, j["hosts_total"]))}
        self.check(len(fns) >= 2, f"[nettopo] only one function colour on the cards: {fns}")
        # option 2: a host with observed conversations lists them in its card
        badge = page.locator("[data-testid=nt-flow-badge]").first
        if self.check(badge.count() == 1, "[nettopo] no flow badge on any host"):
            badge.click()
            page.wait_for_selector("[data-testid=nt-flows]:not([hidden]) div", timeout=5000)
            self.check(page.locator("[data-testid=nt-flows]:not([hidden]) div").count() >= 1, "[nettopo] flow list empty")
            badge.click()
            self.check(page.locator("[data-testid=nt-flows]:not([hidden])").count() == 0, "[nettopo] flow list did not close")
        # egress lane (owner 2026-10-16): destinations outside the site, OT sources in red
        if j["egress"]["destinations"]:
            self.check(page.locator("[data-testid=nt-dest]").count() == len(j["egress"]["destinations"]), "[nettopo] egress destination cards mismatch")
            page.locator("[data-testid=nt-dest]").first.click()
            page.wait_for_selector("[data-testid=nt-dest-row]", timeout=10000)
            self.check(page.locator("[data-testid=nt-dest-approve]").count() >= 1, "[nettopo] egress review drawer has no Approve")
            page.keyboard.press("Escape")
        page.locator("[data-testid=nt-egress]").uncheck()
        self.check(page.locator("[data-testid=nt-egress-lane]").count() == 0, "[nettopo] egress lane still shown")
        page.locator("[data-testid=nt-egress]").check()
        page.locator("[data-testid=nt-inferred]").uncheck()
        self.check(page.locator("[data-testid=nt-lane][data-kind=inferred]").count() == 0, "[nettopo] inferred lanes still shown")
        page.locator("[data-testid=nt-inferred]").check()
        page.locator("[data-testid=nt-host]").first.click()
        page.wait_for_selector("[data-testid=asset-drawer] #ae-save", timeout=15000)
        page.keyboard.press("Escape")
        lane = page.locator("[data-testid=nt-lane][data-kind=fw_interface]").first
        if self.check(lane.count() == 1, "[nettopo] no firewall-interface lane"):
            lane.locator("[data-testid=nt-declare]").click()
            page.wait_for_selector("[data-testid=nt-decl-save]", timeout=10000)
            page.locator("[data-testid=nt-decl-level]").select_option("2")
            page.locator("[data-testid=nt-decl-zone]").fill("Smoke lane <img src=x onerror=window.__xss=1>")
            page.locator("[data-testid=nt-decl-save]").click()
            page.wait_for_function("() => /Saved/.test(document.querySelector('[data-testid=asset-drawer] .form-msg')?.textContent || '')", timeout=10000)
            page.keyboard.press("Escape")
            page.wait_for_selector("[data-testid=nt-lane]", timeout=15000)
            cidr = lane.get_attribute("data-key").replace("net:", "")
            decl = [z for z in self.api(req, "/subnets")["subnets"] if z.get("declaration") and z["cidr"] == cidr]
            self.check(decl and decl[0]["declaration"]["purdue_level"] == 2, "[nettopo] declaration not stored")
        # owner 2026-10-17: several firewalls -> selector shows one firewall's lanes / rules
        fws = j.get("firewalls", [])
        sel = page.locator("[data-testid=nt-fw]")
        self.check(sel.is_hidden() == (len(fws) < 2), "[nettopo] firewall selector visibility vs firewall count")
        if len(fws) >= 2:
            sel.select_option(str(fws[0]["firewall_id"]))
            page.wait_for_selector("[data-testid=nt-sep-fw]", timeout=5000)
            mine = [s for s in j["separators"] if any(t["firewall_id"] == fws[0]["firewall_id"] for t in s["through"])]
            self.check(page.locator("[data-testid=nt-sep][data-fw=selected]").count() == len(mine), "[nettopo] selected-firewall separators vs data")
            self.check(page.locator(".nt-lane.nt-lane-fw").count() == fws[0]["lanes"], "[nettopo] highlighted lanes vs the firewall's lane count")
            sel.select_option("")
            page.wait_for_function("() => !document.querySelector('[data-testid=nt-sep-fw]')", timeout=5000)
        self.shot(page, "nettopo")

    def s_fwports(self, page, req):
        """Owner 2026-10-17: Firewall Ports - one panel per firewall, ports in config order with their
        subnet / VLAN chips, rule services on hover, pinned policy table, table view, disabled toggle."""
        j = self.api(req, "/topology/ports")
        page.wait_for_selector("[data-testid=fp-fw]", timeout=15000)
        self.check(page.locator("[data-testid=fp-fw]").count() == len(j["firewalls"]), "[fwports] firewall panel count")
        up = [p for f in j["firewalls"] for p in f["ports"] if p["status"] != "down"]
        allp = [p for f in j["firewalls"] for p in f["ports"]]
        self.check(page.locator("[data-testid=fp-port]").count() == len(up), f"[fwports] {page.locator('[data-testid=fp-port]').count()} ports shown for {len(up)} up")
        self.check(page.locator("[data-testid=fp-subnet]").count() == sum(len(p["subnets"]) for p in up), "[fwports] subnet chip count")
        self.check(page.locator("[data-testid=fp-subnet] .fp-tag").count() == sum(1 for p in up for s in p["subnets"] if s["tagged"]), "[fwports] VLAN tag count")
        # 2026-10-19: the FortiLink port of FW-LINK names its managed FortiSwitch
        fsw_ports = [p for p in up if p.get("fortiswitches")]
        self.check(len(fsw_ports) >= 1, "[fwports] seed has no FortiLink port with switches")
        self.check(page.locator("[data-testid=fp-fortiswitch]").count() == len(fsw_ports), "[fwports] FortiSwitch line count")
        if fsw_ports:
            self.check("FSW-DEMO-01" in page.locator("[data-testid=fp-fortiswitch]").first.inner_text(), "[fwports] FortiSwitch line text")
        # hover a port that has links: peers light up with service chips
        linked = next((p for p in up if any(l["src_port"] == p["key"] or l["dst_port"] == p["key"] for l in j["links"])), None)
        if linked is not None:
            node = page.locator(f"[data-testid=fp-port][data-key='{linked['key']}']")
            node.hover()
            page.wait_for_selector("[data-testid=fp-hover]", timeout=5000)
            n_links = [l for l in j["links"] if (l["src_port"] == linked["key"]) != (l["dst_port"] == linked["key"])]
            peers = {l["dst_port"] if l["src_port"] == linked["key"] else l["src_port"] for l in n_links}
            lit = page.locator("[data-testid=fp-port].peer-in, [data-testid=fp-port].peer-out, [data-testid=fp-port].peer-both").count()
            self.check(lit == len([k for k in peers if any(p["key"] == k for p in up)]), f"[fwports] {lit} peers lit for {len(peers)}")
            self.check(page.locator(".fp-hover .fp-svc").count() >= 1, "[fwports] no service chip on hover")
            node.click()
            page.wait_for_selector("[data-testid=fp-pin]:not([hidden])", timeout=5000)
            rows = page.locator("[data-testid=fp-pin-row]").count()
            self.check(rows == len([l for l in j["links"] if l["src_port"] == linked["key"] or l["dst_port"] == linked["key"]]), f"[fwports] {rows} pinned rows")
            page.locator("[data-testid=fp-unpin]").click()
            self.check(page.locator("[data-testid=fp-pin]").get_attribute("hidden") is not None, "[fwports] pin table did not close")
        page.locator("[data-testid=fp-disabled]").check()
        page.wait_for_function("(n) => document.querySelectorAll('[data-testid=fp-port]').length === n", arg=len(allp), timeout=5000)
        page.locator("[data-testid=fp-disabled]").uncheck()
        page.locator("[data-testid=fp-table]").check()
        page.wait_for_selector("[data-testid=fp-table-view]", timeout=5000)
        self.check(page.locator("[data-testid=fp-table-view] tbody tr").count() == sum(max(1, len(p["subnets"])) for p in up), "[fwports] table rows")
        if linked is not None:                       # owner 2026-10-18: a table row pins the policies like a card
            page.locator(f"[data-testid=fp-table-row][data-key='{linked['key']}']").first.click()
            page.wait_for_selector("[data-testid=fp-pin]:not([hidden])", timeout=5000)
            self.check(page.locator("[data-testid=fp-pin-row]").count() >= 1, "[fwports] table row did not pin the policies")
            self.check(page.locator("[data-testid=fp-table-row].selected").count() >= 1, "[fwports] pinned port row not marked")
            page.locator("[data-testid=fp-unpin]").click()
        page.locator("[data-testid=fp-table]").uncheck()
        page.wait_for_selector("[data-testid=fp-port]", timeout=5000)
        # a subnet chip opens its lane on Network Topology
        lane_keys = {l["key"] for l in self.api(req, "/topology/subnets")["lanes"]}
        chip = next((c for c in page.locator("[data-testid=fp-subnet][data-cidr]:not([data-cidr=''])").all()
                     if f"net:{c.get_attribute('data-cidr')}" in lane_keys), None)
        if chip is not None:
            cidr = chip.get_attribute("data-cidr")
            chip.click()
            page.wait_for_selector(f"[data-testid=nt-lane][data-key='net:{cidr}']", timeout=15000)
            self.goto(page, "fwports")
            page.wait_for_selector("[data-testid=fp-fw]", timeout=15000)
        self.shot(page, "fwports")

    def s_fw(self, page, req):
        devs = self.api(req, "/firewall-devices")
        self.check(page.locator(".fw-device-card").count() == len(devs), "[fw] device card count mismatch")
        for d in devs:
            card = page.locator(f'.fw-device-card[data-device-id="{d["id"]}"]')
            nums = card.locator(".fw-count .n").all_inner_texts()
            # owner 2026-10-12: the card counts policy lines (grouped), not expanded rows
            self.check(nums[:2] == [str(d["policy_count"]), str(d["disabled_policy_count"])], f"[fw] {d['name']} counts {nums}")
            if d.get("vpn_policy_count"):
                self.check(card.locator("[data-testid=fw-count-vpn] .n").inner_text() == str(d["vpn_policy_count"]),
                           f"[fw] {d['name']} VPN count")
                self.fw_vpn(page, d)
        self.fw_policy_lines(page, req, devs)
        self.fw_config(page, req, devs)
        dis = [d for d in devs if d["disabled_rule_count"]]
        if self.check(dis, "[fw] no device with disabled rules to drill into"):
            d = dis[0]
            page.locator(f'.fw-device-card[data-device-id="{d["id"]}"] button:has-text("Disabled")').click()
            page.wait_for_selector("#fw-rules tr.rule-disabled", timeout=10000)
            n = page.locator("#fw-rules tr.rule-disabled").count()
            self.check(n == d["disabled_rule_count"], f"[fw] drill-down shows {n} disabled rows, expected {d['disabled_rule_count']}")
            self.check("flagged for removal (3.8 / SR 7.7)" in page.locator("#fw-rules").inner_text(), "[fw] disabled label missing")
        # all-rules drill-down per device (by firewall_device_id): count and rule order
        for d in devs:
            page.locator(f'.fw-device-card[data-device-id="{d["id"]}"] button:has-text("Rules")').click()
            page.wait_for_function("(n) => /Rules — /.test(document.getElementById('fw-rules').textContent) && document.querySelectorAll('#fw-rules tbody tr').length === n",
                                   arg=d["rule_count"] + d["disabled_rule_count"], timeout=10000)
            want = d["rule_count"] + d["disabled_rule_count"]
            got = page.locator("#fw-rules tbody tr").count()
            self.check(got == want, f"[fw] {d['name']} drill-down {got} rows != rule_count+disabled {want}")
            orders = [int(t) for t in page.locator("#fw-rules tbody tr td:first-child").all_inner_texts() if t.strip().lstrip("-").isdigit()]
            self.check(orders == sorted(orders), f"[fw] {d['name']} rows not in rule_order: {orders}")
            api_rows = self.api(req, f"/firewall-rules?firewall_device_id={d['id']}")
            self.check(len(api_rows) == want, f"[fw] API firewall_device_id={d['id']} returns {len(api_rows)} != {want}")
        page.locator("#fw-all-disabled").click()
        page.wait_for_load_state("networkidle")
        self.fw_nat(page, req, devs)
        self.fw_last_matched(page, req, devs)

    def fw_policy_lines(self, page, req, devs):
        """One line per policy number (default): groups match the API rows grouped by
        (device, vdom, policy, action, state); members expand on click; untick for one row per rule."""
        d = max(devs, key=lambda d: d["rule_count"] + d["disabled_rule_count"])
        rules = self.api(req, f"/firewall-rules?firewall_device_id={d['id']}")
        page.locator(f'.fw-device-card[data-device-id="{d["id"]}"] button:has-text("Rules")').click()
        page.wait_for_selector("#fw-f-policy", timeout=10000)
        self.check(page.locator("#fw-f-policy").is_checked(), "[fw] policy lines not on by default")
        groups = {}
        for r in rules:
            key = ("p", r["firewall_device_id"], r["vdom"], r["policy_id"], (r["action"] or "").lower(), r["enabled"] is not False) if r["policy_id"] not in (None, "") else ("r", r["id"])
            groups.setdefault(key, []).append(r)
        page.wait_for_function("(n) => document.querySelectorAll('#fw-rules tbody tr').length === n", arg=len(groups), timeout=10000)
        txt = page.locator("[data-testid=fw-rules-count]").inner_text()
        npol = sum(1 for k in groups if k[0] == "p")
        self.check(f"{len(groups)} line" in txt and f"{npol} polic" in txt and f"{len(rules)} row" in txt, f"[fw] policy line count text {txt!r}")
        multi = [(k, v) for k, v in groups.items() if len(v) > 1]
        if self.check(multi, "[fw] seed has no policy with several expanded rows"):
            k, v = max(multi, key=lambda kv: len(kv[1]))
            tr = page.locator(f'#fw-rules tr.rule-policy[data-members="{len(v)}"]').first
            cells = tr.locator("td").all_inner_texts()
            self.check(cells[1] == f"{len(v)} rows" and cells[3].split("\n")[0] == str(v[0]["policy_id"]), f"[fw] policy row cells {cells[:4]}")
            srcs = sorted({r["src"] or "any" for r in v}); dsts = sorted({r["dst"] or "any" for r in v})
            assets = self.api(req, "/assets?limit=10000")
            for cls, vals, label in (("src", srcs, "Sources"), ("dst", dsts, "Destinations")):
                cell = tr.locator(f"td.{cls}")
                self.check(cell.get_attribute("data-scopes") == str(len(vals)), f"[fw] policy row {cls} count")
                cell.hover()
                page.wait_for_selector("[data-testid=host-pop]", timeout=5000)
                page.wait_for_function("() => !/loading/.test(document.querySelector('[data-testid=host-pop]').textContent)", timeout=5000)
                txt = page.locator("[data-testid=host-pop]").inner_text()
                self.check(txt.startswith(f"{label}: {len(vals)} ent"), f"[fw] {cls} host pop head {txt[:40]!r}")
                self.check(all(x.split('/')[0] in txt for x in vals), f"[fw] {cls} host pop misses an address: {txt!r}")
                for x in vals:
                    if x.endswith("/32"):
                        h = next((a for a in assets if a["ip"] == x[:-3]), None)
                        want = (h["hostname"] or h["device_type"] or (f"L{h['purdue_level']}" if h["purdue_level"] is not None else "in inventory")) if h else "not in the inventory"
                        self.check(want in txt, f"[fw] {cls} host pop: {x} -> {want!r} missing: {txt!r}")
                page.mouse.move(0, 0)
                page.wait_for_function("() => !document.querySelector('[data-testid=host-pop]')", timeout=5000)
            self.shot(page, "fw_host_hover")
            ports = {f"{r['protocol'] or 'any'}" for r in v}
            self.check(all(x in tr.locator("td.svc").inner_text() for x in ports), "[fw] policy row services incomplete")
            tr.click()
            page.wait_for_function("(n) => document.querySelectorAll('#fw-rules tr.rule-member').length === n", arg=len(v), timeout=5000)
            ids = sorted(int(x) for x in page.locator("#fw-rules tr.rule-member").evaluate_all("rs => rs.map(r => r.dataset.ruleId)"))
            self.check(ids == sorted(r["id"] for r in v), "[fw] expanded members are not the policy's rows")
            tr.click()
            self.check(page.locator("#fw-rules tr.rule-member:visible").count() == 0, "[fw] members not hidden again")
        self.fw_zone_hover(page, req, d)
        self.fw_classify(page, req)
        self.shot(page, "fw_policy_lines")
        page.locator("#fw-f-policy").uncheck()
        page.wait_for_function("(n) => document.querySelectorAll('#fw-rules tbody tr[data-rule-id]').length === n", arg=len(rules), timeout=10000)
        self.check(not page.locator("#fw-f-policy").is_checked(), "[fw] policy lines did not switch off")

    def fw_classify(self, page, req):
        """Source / Destination hover -> "Classify level / zone": one level + zone saved as a
        Subnets & Zones declaration per ticked IPv4 value (/32 for a host); Enter on the cell
        opens the dialog without expanding the policy line, Escape closes it.  The
        declarations are deleted again so later sections see the seeded levels."""
        import re as _re
        ipv4 = _re.compile(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$")
        cells = page.locator("#fw-rules tr.rule-policy td.host-cell")
        cell, vals = None, []
        for i in range(cells.count()):
            c = cells.nth(i)
            vs = [x for x in c.inner_text().split("\n") if ipv4.match(x.strip())]
            if vs:
                cell, vals = c, [x.strip() for x in vs]
                break
        if not self.check(cell is not None, "[fw_classify] no Source / Destination cell with an IPv4 value"):
            return
        cidrs = sorted({v if "/" in v else v + "/32" for v in vals})
        site = self.api(req, "/firewall-rules")[0]["site_id"]
        before = {(a["id"], a["ip"]): a["purdue_level"] for a in self.api_all(req, f"/assets?site_id={site}&limit=10000")}
        # hover -> pop-up stays open while the pointer moves into it -> button
        cell.hover()
        page.wait_for_selector("[data-testid=host-pop-classify]", timeout=5000)
        page.locator("[data-testid=host-pop-classify]").hover()
        self.check(page.locator("[data-testid=host-pop]").is_visible(), "[fw_classify] pop-up closed when the pointer moved into it")
        page.locator("[data-testid=host-pop-classify]").click()
        dlg = page.locator("[data-testid=fw-classify-dialog]")
        dlg.wait_for(state="visible", timeout=5000)
        page.wait_for_selector("[data-testid=fwcls-row]", timeout=5000)
        rows = dlg.locator("[data-testid=fwcls-row]")
        got = sorted(rows.nth(i).get_attribute("data-cidr") for i in range(rows.count()))
        self.check(set(got) <= set(cidrs) and len(got) >= 1, f"[fw_classify] dialog values {got} vs cell {cidrs}")
        zone = "Smoke zone <img src=x onerror=window.__xss=1>"
        dlg.locator("[data-testid=fwcls-level]").select_option("2")
        dlg.locator("[data-testid=fwcls-zone]").fill(zone)
        dlg.locator("[data-testid=fwcls-save]").click()
        page.wait_for_function("() => /Saved \\d+ declaration/.test(document.querySelector('[data-testid=fwcls-msg]')?.textContent || '')", timeout=10000)
        decl = {fr["cidr"]: fr["declaration"] for fr in self.api(req, f"/subnets?site_id={site}")["subnets"] if fr.get("declaration")}
        mine = {c: decl.get(c) for c in got}
        self.check(all(d_ and d_["zone_name"] == zone and d_["purdue_level"] == 2 for d_ in mine.values()),
                   f"[fw_classify] declarations not stored: {mine}")
        self.check(all(dlg.locator(f'[data-testid=fwcls-row][data-cidr="{c}"] [data-testid=fwcls-current]').inner_text().startswith("L2") for c in got),
                   "[fw_classify] 'Declared now' not updated")
        self.check(dlg.locator("[data-testid=fwcls-run-reviews]").is_visible(), "[fw_classify] no Run reviews button after saving")
        self.shot(page, "fw_classify")
        dlg.locator("[data-testid=fw-classify-close]").click()
        page.wait_for_function("() => !document.getElementById('fwcls-dialog').open", timeout=5000)
        # keyboard: Enter on the cell opens the dialog (the policy line stays collapsed), Escape closes
        page.wait_for_selector("#fw-rules tr.rule-policy td.host-cell", timeout=10000)
        c2 = page.locator("#fw-rules tr.rule-policy td.host-cell").first
        c2.focus()
        c2.press("Enter")
        self.check(dlg.is_visible(), "[fw_classify] Enter on the cell did not open the dialog")
        self.check(page.locator("#fw-rules tr.rule-policy").first.get_attribute("aria-expanded") == "false",
                   "[fw_classify] Enter also expanded the policy line")
        page.keyboard.press("Escape")
        page.wait_for_function("() => !document.getElementById('fwcls-dialog').open", timeout=5000)
        # clean up: remove the declarations, the seeded levels come back
        for d_ in mine.values():
            if d_:
                req.delete(f"{self.base}/subnets/{d_['id']}?site_id={site}")
        after = {(a["id"], a["ip"]): a["purdue_level"] for a in self.api_all(req, f"/assets?site_id={site}&limit=10000")}
        changed = [k for k in before if k in after and before[k] != after[k]]
        self.check(not changed, f"[fw_classify] levels not restored after deleting the declarations: {changed[:5]}")

    def fw_zone_hover(self, page, req, d):
        """Hovering a zone / interface name in the rules table shows its networks and the inventory hosts in them."""
        import ipaddress
        zones = [z for z in self.api(req, "/firewall-zones") if z["device_name"] == d["name"]]
        # interface aliases (config `set alias`) shown in grey on the device card, like Subnets & Zones
        aliased = [z for z in zones if z.get("alias")]
        card_txt = page.locator(f'.fw-device-card[data-device-id="{d["id"]}"]').inner_text()
        self.check(all(z["alias"] in card_txt for z in aliased[:10]), f"[fw_zone_hover] alias missing on the device card: {[z['alias'] for z in aliased]}")
        toks = page.locator("#fw-rules td.zones .zone-tok:not(.zone-unknown)")
        if not self.check(toks.count() > 0, f"[fw] {d['name']}: no known zone token in the rules table"):
            return
        tok = toks.first
        name = tok.get_attribute("data-zone")
        rows = [z for z in zones if name.lower() in {str(z["interface_name"]).lower(), str(z["zone_name"] or "").lower()}]
        tok.hover()
        page.wait_for_selector("[data-testid=zone-pop]", timeout=5000)
        nets = {z["ip_cidr"] for z in rows if z["ip_cidr"]}
        hosts = [h for h in self.api(req, "/assets?limit=10000") if h["ip"] and any(ipaddress.ip_address(h["ip"]) in ipaddress.ip_network(n, strict=False) for n in nets)]
        page.wait_for_function("() => !/loading/.test(document.querySelector('[data-testid=zone-pop]').textContent)", timeout=5000)
        txt = page.locator("[data-testid=zone-pop]").inner_text()
        self.check(all(n in txt for n in nets), f"[fw] zone pop for {name}: networks {nets} not all shown: {txt!r}")
        if hosts:
            self.check(f"{len(hosts)} host" in txt, f"[fw] zone pop for {name}: host count {len(hosts)} not shown: {txt!r}")
            self.check(all(h["ip"] in txt for h in hosts[:3]), f"[fw] zone pop for {name}: hosts missing")
        else:
            self.check("No hosts" in txt, f"[fw] zone pop for {name}: expected no hosts: {txt!r}")
        self.shot(page, "fw_zone_hover")
        page.mouse.move(0, 0)
        page.wait_for_function("() => !document.querySelector('[data-testid=zone-pop]')", timeout=5000)
        unknown = page.locator("#fw-rules td.zones .zone-tok.zone-unknown")
        if unknown.count():
            unknown.first.hover()
            page.wait_for_selector("[data-testid=zone-pop]", timeout=5000)
            self.check("No interface or zone" in page.locator("[data-testid=zone-pop]").inner_text(), "[fw] unknown zone pop text")
            page.mouse.move(0, 0)
            page.wait_for_function("() => !document.querySelector('[data-testid=zone-pop]')", timeout=5000)

    def fw_nat(self, page, req, devs):
        """F-05: NAT count per device + drill-down from GET /nat-rules."""
        nat = self.api(req, "/nat-rules")
        r = req.get(self.base + "/nat-rules?limit=1")
        self.check(int(r.headers["x-total-count"]) == len(nat), "[fw] /nat-rules X-Total-Count wrong")
        self.check(req.get(self.base + "/nat-rules?nat_type=bogus").status == 422, "[fw] bad nat_type not rejected")
        def mine(d):
            return [n for n in nat if n["firewall_device_id"] == d["id"]
                    or (n["firewall_device_id"] is None and d["firewall_id"] is not None and n["firewall_id"] == d["firewall_id"])]

        def nat_groups(d):
            keys = {}
            for n in mine(d):
                pol = f"p{n['policy_id']}" if n.get("policy_id") not in (None, "") else (f"n{n['name']}" if n.get("name") else f"r{n['id']}")
                keys.setdefault((n["nat_type"], n.get("firewall_device_id") or n.get("firewall_id"), n.get("vdom"), pol,
                                 n.get("enabled") is not False), []).append(n["id"])
            return keys
        for d in devs:
            got = page.locator(f'.fw-device-card[data-device-id="{d["id"]}"] .fw-count.nat .n').inner_text()
            self.check(got == str(len(nat_groups(d))), f"[fw] {d['name']} NAT count {got} != {len(nat_groups(d))} policies")
        withnat = [d for d in devs if mine(d)]
        if self.check(withnat, "[fw] seed has no device with NAT"):
            d = withnat[0]
            page.locator(f'.fw-device-card[data-device-id="{d["id"]}"] button[data-action="nat"]').click()
            page.wait_for_selector("#fw-rules [data-testid=nat-table]", timeout=10000)
            # one line per NAT policy (owner 2026-10-12): lines = groups of (type, device, vdom,
            # policy or VIP name, state); each line's members = its translations
            if not page.locator("#fw-nat-policy").is_checked():
                page.locator("#fw-nat-policy").check()
                page.wait_for_selector("#fw-rules [data-testid=nat-table]", timeout=10000)
            keys = nat_groups(d)
            lines = page.locator("#fw-rules [data-testid=nat-table] tbody tr")
            self.check(lines.count() == len(keys), f"[fw] NAT policy lines {lines.count()} != {len(keys)} groups")
            multi = page.locator("#fw-rules [data-testid=nat-table] tbody tr.rule-policy")
            if multi.count():
                m0 = multi.first
                n_mem = int(m0.get_attribute("data-members"))
                m0.click()
                self.check(page.locator("#fw-rules [data-testid=nat-table] tbody tr.rule-member").count() == n_mem,
                           "[fw] NAT policy line did not expand to its translations")
                self.shot(page, "fw_nat_policy_lines")
            page.locator("#fw-nat-policy").uncheck()
            page.wait_for_selector("#fw-rules [data-testid=nat-table]", timeout=10000)
            rows = page.locator("#fw-rules [data-testid=nat-table] tbody tr")
            self.check(rows.count() == len(mine(d)), f"[fw] NAT drill-down rows {rows.count()} != {len(mine(d))}")
            txt = page.locator("#fw-rules").inner_text()
            for n in mine(d):
                self.check((n["name"] or "") in txt, f"[fw] NAT name {n['name']!r} not shown as text")
                self.check(f"{n['ext_ip'] if n['nat_type'] == 'dnat' else (n['orig_src'] or 'any')} → {n['mapped_ip']}" in txt,
                           f"[fw] NAT {n['id']} ext/source → mapped not shown")
                cells = page.locator(f'#fw-rules tr[data-nat-id="{n["id"]}"] td').all_inner_texts()
                self.check(cells[0] == n["nat_type"].upper() and cells[6] == (n["policy_id"] or "—"), f"[fw] NAT row cells {cells}")
            self.shot(page, "fw_nat")
            page.locator("#fw-nat-policy").check()           # leave the default view on

    def fw_vpn(self, page, d):
        """VPN (n) opens the rules filtered to VPN policies: one badged line each (the
        tunnel kind and direction), untick shows every policy again."""
        page.locator(f'.fw-device-card[data-device-id="{d["id"]}"] [data-testid=fw-vpn-button]').click()
        page.wait_for_selector("#fw-rules [data-testid=fw-vpn-only]", timeout=10000)
        self.check(page.locator("#fw-f-vpn").is_checked(), "[fw_vpn] VPN filter not on")
        badges = page.locator("#fw-rules tbody tr [data-testid=fw-vpn-badge]")
        lines = page.locator("#fw-rules tbody tr.rule-policy, #fw-rules tbody tr[data-rule-id]:not(.rule-member)")
        self.check(lines.count() == d["vpn_policy_count"] and badges.count() == d["vpn_policy_count"],
                   f"[fw_vpn] {lines.count()} lines / {badges.count()} badges != {d['vpn_policy_count']} VPN policies")
        self.check(all("VPN · " in t for t in badges.all_inner_texts()), "[fw_vpn] badge text")
        page.locator("#fw-f-vpn").uncheck()
        self.check(page.locator("#fw-rules tbody tr.rule-policy, #fw-rules tbody tr[data-rule-id]:not(.rule-member)").count()
                   >= d["vpn_policy_count"], "[fw_vpn] unticking did not show every policy")

    def fw_last_matched(self, page, req, devs):
        """F-10: last matched (relative + tooltip), sort, never-matched enabled permits."""
        rules_all = self.api(req, "/firewall-rules")
        dev = max(devs, key=lambda d: sum(1 for r in rules_all if r["firewall_device_id"] == d["id"] and r["last_matched"]))
        rules = [r for r in rules_all if r["firewall_device_id"] == dev["id"]]
        page.locator(f'.fw-device-card[data-device-id="{dev["id"]}"] button:has-text("Rules")').click()
        page.wait_for_function("(n) => document.querySelectorAll('#fw-rules tbody tr[data-rule-id]').length === n", arg=len(rules), timeout=10000)
        matched = [r for r in rules if r["last_matched"]]
        self.check(matched, f"[fw] {dev['name']}: no rule with last_matched in the seed")
        for r in matched:
            t = page.locator(f'#fw-rules tr[data-rule-id="{r["id"]}"] td:last-child time')
            self.check(t.count() == 1 and re.search(r"ago|just now", t.inner_text()) and t.get_attribute("title"),
                       f"[fw] rule {r['id']}: last matched not relative+tooltip")
        unm = [r for r in rules if r["enabled"] and (r["action"] or "").lower() in PERMIT and not r["last_matched"]]
        self.check(page.locator("#fw-rules tr.rule-unmatched").count() == len(unm), f"[fw] never-matched highlight {page.locator('#fw-rules tr.rule-unmatched').count()} != {len(unm)}")
        if unm:
            self.check(f"{len(unm)} enabled permit" in page.locator("#fw-rules [data-testid=unmatched-count]").inner_text(), "[fw] never-matched count badge")
        page.locator('#fw-rules button[data-sort="last_matched"]').click()
        ids = [int(x) for x in page.locator("#fw-rules tbody tr[data-rule-id]").evaluate_all("rs => rs.map(r => r.dataset.ruleId)")]
        want = [r["id"] for r in sorted(matched, key=lambda r: r["last_matched"], reverse=True)]
        self.check(ids[:len(want)] == want, f"[fw] sort by last matched (desc): {ids[:len(want)]} != {want}")
        page.locator('#fw-rules button[data-sort="last_matched"]').click()
        ids = [int(x) for x in page.locator("#fw-rules tbody tr[data-rule-id]").evaluate_all("rs => rs.map(r => r.dataset.ruleId)")]
        self.check(ids[:len(want)] == want[::-1], "[fw] sort by last matched (asc) wrong")
        self.check(page.locator("#fw-rules tbody tr[data-rule-id] td:last-child").last.inner_text().strip() in ("never matched", "—") or len(matched) == len(rules),
                   "[fw] never-matched rows not sorted last")
        self.shot(page, "fw_rules_last_matched")
        page.locator('#fw-rules button[data-sort="order"]').click()

    def fwtopo_disabled(self, page, st):
        """Default view: enabled interfaces only; Show disabled interfaces adds the
        administratively-down ones, greyed out (iface-disabled + a "disabled" badge)."""
        ifs = [i for f in st["firewalls"] for i in f["interfaces"]]   # every section is drawn (HA, mgmt, vdom links too)
        on = [i for i in ifs if i.get("enabled", True)]
        box = page.locator("#fwt-show-disabled")
        if box.is_checked():
            box.uncheck()
        self.check(page.locator("#fwt-wrap .iface-card").count() == len(on),
                   f"[fwtopo_disabled] default view shows {page.locator('#fwt-wrap .iface-card').count()} cards, {len(on)} enabled interfaces")
        self.check(page.locator("#fwt-wrap .iface-card.iface-disabled").count() == 0, "[fwtopo_disabled] disabled card shown by default")
        box.check()
        self.check(page.locator("#fwt-wrap .iface-card").count() == len(ifs), "[fwtopo_disabled] ticked view does not show every interface")
        off = len(ifs) - len(on)
        self.check(page.locator("#fwt-wrap .iface-card.iface-disabled").count() == off
                   and page.locator("#fwt-wrap [data-testid=fwt-iface-disabled]").count() == off,
                   f"[fwtopo_disabled] {off} disabled interfaces, cards greyed: {page.locator('#fwt-wrap .iface-card.iface-disabled').count()}")
        box.uncheck()

    def fwtopo_config_settings(self, page, req, st):
        """Owner 2026-10-14 (option 3): the selected interface's settings from the stored config -
        key / value table, raw block, Open in config."""
        page.wait_for_selector("[data-testid=fwt-cfg-row], [data-testid=fwt-cfg-none]", timeout=15000)
        rows = page.locator("[data-testid=fwt-cfg-row]")
        if not self.check(rows.count() >= 1, "[fwtopo_cfg] no settings rows for the first interface"):
            return
        keys = [rows.nth(k).get_attribute("data-key") for k in range(rows.count())]
        self.check("ip" in keys or "vdom" in keys or "type" in keys, f"[fwtopo_cfg] unexpected keys {keys}")
        page.locator("[data-testid=fwt-cfg-settings] summary").click()
        self.check(page.locator("[data-testid=fwt-cfg-line]").count() >= 2, "[fwtopo_cfg] raw block empty")
        page.locator("[data-testid=fwt-cfg-open]").click()
        page.wait_for_selector("[data-testid=asset-drawer] [data-testid=cfg-view]", timeout=15000)
        self.check(page.locator("[data-testid=asset-drawer] [data-testid=cfg-line].focus").count() == 1, "[fwtopo_cfg] Open in config did not focus the block")
        self.shot(page, "fwtopo_cfg")
        page.keyboard.press("Escape")
        self.check(page.locator("[data-testid=asset-drawer]").is_hidden(), "[fwtopo_cfg] drawer did not close")

    def s_fwtopo(self, page, req):
        st = self.api(req, "/topology/state")
        self.check(page.locator(".fw-column").count() == len(st["firewalls"]), "[fwtopo] column count mismatch")
        self.fwtopo_disabled(page, st)
        al = [i["alias"] for f in st["firewalls"] for i in f["interfaces"] if i.get("alias") and i.get("enabled", True)]
        got = page.locator("#fwt-wrap [data-testid=fwt-iface-alias]").all_inner_texts()
        self.check(sorted(got) == sorted(al), f"[fwtopo] interface aliases {got} != {al}")
        cards = page.locator(".iface-card")
        if self.check(cards.count() > 0, "[fwtopo] no interface cards"):
            cards.first.click()
            self.check(page.locator('#fwt-rp-body button:has-text("Save labels")').count() == 1, "[fwtopo] interface editor missing")
            self.fwtopo_config_settings(page, req, st)
            page.locator("#fwt-zone").fill("Smoke zone")
            page.locator('#fwt-rp-body button:has-text("Save labels")').click()
            page.wait_for_selector('.iface-card .badge:has-text("Smoke zone")', timeout=10000)
        pcap = ROOT / "sample_data" / "multi_protocol_sample.pcap"
        if pcap.exists():
            # multi-site: the upload is refused client-side until a site is chosen
            page.locator("#fwt-pcap-site").select_option("")
            page.locator("#fwt-pcap-file").set_input_files(str(pcap))
            page.locator("#fwt-pcap-upload").click()
            page.wait_for_function("() => /Choose the site/.test(document.getElementById('fwt-pcap-result').textContent)", timeout=5000)
            page.locator("#fwt-pcap-site").select_option(str(self.site_id(req, "plant-a")))
            page.locator("#fwt-pcap-upload").click()
            page.wait_for_selector("#fwt-pcap-result .pcap-suggestion", timeout=30000)
            page.locator('#fwt-pcap-result button:has-text("Confirm assignment")').click()
            page.wait_for_function("() => /Confirmed: capture/.test(document.getElementById('fwt-pcap-result').textContent)", timeout=10000)
            caps = self.api(req, f"/topology/firewalls?site_id={self.site_id(req, 'plant-a')}")["firewalls"]
            self.check(any(f["capture_count"] for f in caps), "[fwtopo] PCAP capture not stored in Plant A")
        props = st["pending_proposals"]
        if props:
            page.locator('.proposal-card button:has-text("Show")').first.click()
            page.locator('.proposal-card button:has-text("Confirm")').first.click()
            page.wait_for_function("() => /confirm-link/.test(document.getElementById('fwt-action-result').textContent)", timeout=15000)
            page.wait_for_load_state("networkidle")
            self.check(len(self.api(req, "/topology/state")["pending_proposals"]) < len(props), "[fwtopo] confirm-link did not consume a proposal")
            self.check(page.locator("#fwt-svg path").count() >= 1, "[fwtopo] no link drawn after confirm")

    def s_zones(self, page, req):
        """RS G3: one row per subnet the API lists; declaring a zone from a row
        saves it, and Clear removes it again."""
        d = self.api(req, "/subnets")
        rows = d["subnets"]
        self.check(page.locator("[data-testid=zone-row]").count() == len(rows), "[zones] row count != /subnets")
        if not self.check(rows, "[zones] seed has no subnet"):
            return
        cidr = rows[0]["cidr"]
        row = page.locator(f'[data-testid=zone-row][data-cidr="{cidr}"]')
        row.locator("[data-testid=zone-level]").select_option("3")
        row.locator("[data-testid=zone-name]").fill("Smoke zone")
        row.locator("[data-testid=zone-save]").click()
        page.wait_for_selector(f'[data-testid=zone-row][data-cidr="{cidr}"] [data-testid=zone-clear]', timeout=15000)
        got = {s_["cidr"]: s_ for s_ in self.api(req, "/subnets")["subnets"]}[cidr]["declaration"]
        self.check(got and got["purdue_level"] == 3 and got["zone_name"] == "Smoke zone", "[zones] declaration not saved")
        page.locator(f'[data-testid=zone-row][data-cidr="{cidr}"] [data-testid=zone-clear]').click()
        page.wait_for_selector(f'[data-testid=zone-row][data-cidr="{cidr}"] [data-testid=zone-save]:has-text("Save")', timeout=15000)
        got = {s_["cidr"]: s_ for s_ in self.api(req, "/subnets")["subnets"]}[cidr]["declaration"]
        self.check(got is None, "[zones] Clear did not remove the declaration")

    def s_iec(self, page, req):
        """IEC 62443-3-2 zones and conduits: documentation only.  Create two
        zones from the page (one spanning two subnets / levels), document a
        conduit, check the page against the API and that findings did not
        change; remove the zones again."""
        def fsum():
            return self.api(req, "/findings/summary")
        before = fsum()
        pre = {z["id"] for z in self.api(req, "/iec-zones")["zones"]}     # e.g. from the inventory CSV zone column
        self.check(page.locator("[data-testid=iec-zone-row]").count() == len(pre), "[iec] zone rows != API before the test")
        self.check(page.locator("[data-testid=iec-doc-only]").count() == 1, "[iec] documentation-only note missing")
        cand = self.api(req, "/iec-zones/candidates")
        subnets = [x["ref"] for x in cand["subnets"] if not x["zone"]]
        if not self.check(len(subnets) >= 2, f"[iec] seed has fewer than two subnets: {subnets}"):
            return
        made = []
        for name, sl in (("Smoke cell", "3"), ("Smoke ops", "2")):
            page.locator("[data-testid=iec-new-name]").fill(name)
            page.locator("[data-testid=iec-new-add]").locator("xpath=..").locator("[data-testid=iec-sl]").select_option(sl)
            page.locator("[data-testid=iec-new-add]").click()
            page.wait_for_selector(f'[data-testid=iec-zone-panel] h3:has-text("Zone: {name}")', timeout=15000)
            made.append(next(z for z in self.api(req, "/iec-zones")["zones"] if z["name"] == name))
        self.check([z["sl_t"] for z in made] == [3, 2], f"[iec] SL-T not saved: {[z['sl_t'] for z in made]}")
        # members: the cell gets two subnets (two levels possible), ops gets nothing yet
        cell = made[0]
        page.locator(f'[data-testid=iec-zone-row][data-zone-id="{cell["id"]}"]').click()
        panel = page.locator(f'[data-testid=iec-zone-panel][data-zone-id="{cell["id"]}"]')
        for ref in subnets[:2]:
            panel = page.locator(f'[data-testid=iec-zone-panel][data-zone-id="{cell["id"]}"]')
            panel.locator("[data-testid=iec-add-kind]").select_option("subnet")
            panel.locator("[data-testid=iec-add-ref]").fill(ref)
            panel.locator("[data-testid=iec-add-btn]").click()
            page.wait_for_selector(f'[data-testid=iec-zone-panel][data-zone-id="{cell["id"]}"] [data-testid=iec-member-row][data-ref="{ref}"]', timeout=15000)
        z = next(x for x in self.api(req, "/iec-zones")["zones"] if x["id"] == cell["id"])
        row = page.locator(f'[data-testid=iec-zone-row][data-zone-id="{cell["id"]}"]')
        self.check(row.locator("[data-testid=iec-zone-hosts]").inner_text().strip() == str(z["host_count"]),
                   "[iec] zone host count != API")
        self.check(row.locator("[data-testid=iec-zone-levels] .lvl-badge").count() == len(z["purdue_levels"]),
                   "[iec] Purdue levels of the zone not shown")
        # a second claim on the same subnet is allowed and listed (reported by network_in_multiple_zones)
        r = req.post(self.base + f"/iec-zones/{made[1]['id']}/members?site_id={self.cur_site}",
                     data='{"kind": "subnet", "ref": "%s"}' % subnets[0], headers={"Content-Type": "application/json"})
        self.check(r.status == 200, f"[iec] second zone for one subnet refused: {r.status}")
        page.evaluate("() => loadIec()")
        page.wait_for_selector("[data-testid=iec-overlaps]", timeout=15000)
        ov = self.api(req, "/iec-zones")["overlaps"]
        self.check(any(o["network"] == subnets[0] for o in ov), "[iec] overlap not listed")
        mid = next(m["id"] for z in self.api(req, "/iec-zones")["zones"] if z["id"] == made[1]["id"] for m in z["members"])
        req.delete(self.base + f"/iec-zones/members/{mid}?site_id={self.cur_site}")
        page.evaluate("() => loadIec()")
        page.wait_for_function("() => !document.querySelector('[data-testid=iec-overlaps]')", timeout=15000)
        page.wait_for_load_state("networkidle")
        # owner 2026-10-13: every SL dropdown offers SL0 - SL4 with their labels; the
        # conduit add card has SL-A; Subnets & Zones is a sub-item of Zones & Conduits
        want = ["SL0 - No Requirements", "SL1 - Casual/Accidents", "SL2 - Simple Intentional Means",
                "SL3 - Sophisticated Attacks", "SL4 - Advanced Resources"]
        for tid in ("iec-sl", "iec-new-sla", "iec-cd-sla", "iec-zone-sla-edit", "iec-slc-select"):
            loc = page.locator(f"[data-testid={tid}]")
            if self.check(loc.count() >= 1, f"[iec] no {tid} dropdown"):
                self.check(loc.first.locator("option").all_inner_texts()[1:] == want, f"[iec] {tid} options")
        nav = page.locator(".nav-item").evaluate_all("ns => ns.map(n => n.dataset.page)")
        self.check(nav.index("zones") == nav.index("iec") + 1
                   and "nav-sub" in (page.locator("[data-testid=nav-zones]").get_attribute("class") or ""),
                   "[iec] Subnets & Zones is not the sub-item under Zones & Conduits")
        # document the conduit (SL-A on the add card)
        page.locator("[data-testid=iec-cd-a]").select_option(str(made[0]["id"]))
        page.locator("[data-testid=iec-cd-b]").select_option(str(made[1]["id"]))
        page.locator("[data-testid=iec-cd-name]").fill("Smoke conduit")
        page.locator("[data-testid=iec-cd-sla]").select_option("0")
        page.locator("[data-testid=iec-cd-add]").click()
        page.wait_for_selector('[data-testid=iec-conduit-row]', timeout=15000)
        cv = self.api(req, "/iec-conduits")
        self.check([c["name"] for c in cv["conduits"]] == ["Smoke conduit"] and cv["conduits"][0]["sl_a"] == 0,
                   "[iec] conduit (with SL-A 0) not saved")
        # firewall rule numbers on the conduit: a chip with a hover card
        dev = next(iter(cv["devices"]), None)
        fw_name = dev["name"] if dev else None
        pol = next((r["policy_id"] for r in self.api(req, "/firewall-rules?limit=500")
                    if dev and r.get("policy_id") and r.get("firewall_id") == dev["id"]), None)
        if fw_name and pol:
            crow0 = page.locator("[data-testid=iec-conduit-row]").first
            crow0.locator("[data-testid=iec-cd-rule-fw]").fill(fw_name)
            crow0.locator("[data-testid=iec-cd-rule-ids]").fill(str(pol))
            with page.expect_response(lambda r: "/rules" in r.url and r.request.method == "POST"):
                crow0.locator("[data-testid=iec-cd-rule-add]").click()
            page.wait_for_selector("[data-testid=iec-cd-rule]", timeout=15000)
            page.locator("[data-testid=iec-cd-rule]").first.hover()
            pop = page.locator("[data-testid=iec-cd-rule-pop]")
            self.check(pop.count() == 1 and f"#{pol}" in pop.inner_text() and "Source" in pop.inner_text(),
                       "[iec] rule hover card missing")
            page.mouse.move(2, 2)
            self.check(self.api(req, "/iec-conduits")["conduits"][0]["rules"][0]["policy_id"] == str(pol),
                       "[iec] attached rule not in the API")
        self.check(page.locator("[data-testid=iec-und-row]").count() == len(cv["undocumented"]),
                   "[iec] undocumented pair rows != API")
        # SL-A: the cell (SL-T 3) assessed at SL-A 2 from the zone panel -> below target
        if not page.locator(f'[data-testid=iec-zone-panel][data-zone-id="{cell["id"]}"]').count():
            page.locator(f'[data-testid=iec-zone-row][data-zone-id="{cell["id"]}"]').click()
        panel = page.locator(f'[data-testid=iec-zone-panel][data-zone-id="{cell["id"]}"]')
        panel.locator("[data-testid=iec-sla-select]").select_option("2")
        panel.locator("[data-testid=iec-sla-note]").fill("smoke assessment")
        panel.locator("[data-testid=iec-edit-save]").click()
        page.wait_for_selector(f'[data-testid=iec-zone-panel][data-zone-id="{cell["id"]}"] [data-testid=iec-zone-sla-below]', timeout=15000)
        z = next(x for x in self.api(req, "/iec-zones")["zones"] if x["id"] == cell["id"])
        self.check((z["sl_a"], z["sl_a_note"], z["sl_a_status"]) == (2, "smoke assessment", "below"),
                   f"[iec] zone SL-A not saved: {z.get('sl_a')} {z.get('sl_a_status')}")
        self.check(page.locator(f'[data-testid=iec-zone-row][data-zone-id="{cell["id"]}"] [data-testid=iec-zone-sla-edit]').input_value() == "2",
                   "[iec] zone row does not show the SL-A")
        crow = page.locator("[data-testid=iec-conduit-row]").first
        with page.expect_response(lambda r: "/iec-conduits/" in r.url and r.request.method == "PATCH"):
            crow.locator("[data-testid=iec-sla-select]").select_option("1")
        page.wait_for_selector("[data-testid=iec-conduit-sla-below]", timeout=15000)
        self.check(self.api(req, "/iec-conduits")["conduits"][0]["sl_a"] == 1, "[iec] conduit SL-A not saved")
        # option 3: services on the conduit; covered findings are shown one step lower, with the reason
        crow.locator("[data-testid=iec-cd-services]").fill("any")
        with page.expect_response(lambda r: "/iec-conduits/" in r.url and r.request.method == "PATCH"):
            crow.locator("[data-testid=iec-cd-services-save]").click()
        page.wait_for_load_state("networkidle")
        self.check(self.api(req, "/iec-conduits")["conduits"][0]["services"] == "any", "[iec] conduit services not saved")
        fl3 = self.api(req, "/findings?limit=500")
        lowered = [f for f in fl3 if f["severity_adjustment"]]
        on_conduit = [f for f in fl3 if (f["zone_judgement"] or {}).get("documentation") == "documented"
                      and f["check_name"] not in ("session_ot_internet_egress", "path_ot_internet_egress")]
        self.check(len(lowered) == len(on_conduit), f"[iec] lowered {len(lowered)} != findings on the conduit {len(on_conduit)}")
        self.check(all(f["shown_severity"] != f["severity"] or f["severity"] in ("low", "info") for f in lowered),
                   "[iec] lowered finding shows the recorded severity")
        if lowered:
            self.goto(page, "findings")
            page.wait_for_selector("[data-testid=finding-sev-lowered]", timeout=15000)
            self.check(page.locator("[data-testid=finding-sev-lowered]").count() >= 1, "[iec] lowered badge not shown")
            self.goto(page, "iec")
        crow = page.locator("[data-testid=iec-conduit-row]").first
        crow.locator("[data-testid=iec-cd-services]").fill("")
        with page.expect_response(lambda r: "/iec-conduits/" in r.url and r.request.method == "PATCH"):
            crow.locator("[data-testid=iec-cd-services-save]").click()
        page.wait_for_load_state("networkidle")
        self.check(not any(f["severity_adjustment"] for f in self.api(req, "/findings?limit=500")), "[iec] lowering did not revert")
        # findings are judged against the zone SL-T (view only)
        fl = self.api(req, "/findings?limit=500")
        self.check(all("zone_judgement" in f for f in fl), "[iec] findings lack zone_judgement")
        judged = [f for f in fl if f["zone_judgement"]]
        for v in ("applies", "beyond", "no_sl_t", "no_zone"):
            got = self.api(req, f"/findings?limit=500&zone_scope={v}")
            want = [f["id"] for f in fl if (f["zone_judgement"] or {}).get("verdict", "no_zone") == v]
            self.check(sorted(f["id"] for f in got) == sorted(want), f"[iec] zone_scope={v} != row judgements")
        self.check(page.locator("#f-zone option").count() == 5, "[iec] findings zone filter missing")
        self.check(page.locator("#f-conduit option").count() == 6, "[iec] findings conduit filter missing")
        for v in ("intra_zone", "documented", "undocumented", "partial", "external"):
            got = self.api(req, f"/findings?limit=500&conduit_doc={v}")
            want = [f["id"] for f in fl if (f["zone_judgement"] or {}).get("documentation") == v]
            self.check(sorted(f["id"] for f in got) == sorted(want), f"[iec] conduit_doc={v} != row judgements")
        # option 4: the zone pairs communicating with no conduit are findings after a review run
        cv = self.api(req, "/iec-conduits")
        pairs = {frozenset((u["zone_a"]["name"], u["zone_b"]["name"])) for u in cv["undocumented"] if u["declarable"]}
        r = req.post(self.base + f"/reviews/run?site_id={self.cur_site}")
        self.check(r.ok, f"[iec] review run {r.status}")
        uc = self.api(req, "/findings?limit=500&check_name=undocumented_conduit&status=open")
        got_pairs = {frozenset((f["detail"]["zone_a"], f["detail"]["zone_b"])) for f in uc}
        self.check(got_pairs == pairs, f"[iec] undocumented_conduit findings {got_pairs} != page pairs {pairs}")
        before = fsum()                      # the rest of the findings summary is compared after the zones are removed
        print(f"  [iec] {len(judged)} of {len(fl)} findings judged against a zone SL-T")
        # SL-C: a host in the cell zone (SL-T 3) set to SL-C 1 from the zone panel -> below target
        page.locator(f'[data-testid=iec-zone-row][data-zone-id="{cell["id"]}"]').click() if not page.locator(
            f'[data-testid=iec-zone-panel][data-zone-id="{cell["id"]}"]').count() else None
        hrow = page.locator(f'[data-testid=iec-zone-panel][data-zone-id="{cell["id"]}"] [data-testid=iec-zone-host-row]').first
        if hrow.count():
            ip = hrow.get_attribute("data-ip")
            with page.expect_response(lambda r: "/assets/" in r.url and r.request.method == "PATCH"):
                hrow.locator("[data-testid=iec-slc-select]").select_option("1")
            page.wait_for_selector(f'[data-testid=iec-zone-panel] [data-testid=iec-zone-host-row][data-ip="{ip}"] [data-testid=iec-host-below]', timeout=15000)
            z = next(x for x in self.api(req, "/iec-zones")["zones"] if x["id"] == cell["id"])
            self.check(ip in [b["ip"] for b in z["sl_c"]["below_target"]], "[iec] host SL-C 1 not below SL-T 3 in the API")
            self.check(page.locator(f'[data-testid=iec-zone-row][data-zone-id="{cell["id"]}"] [data-testid=iec-zone-slc-below]').count() == 1,
                       "[iec] zone row does not show the SL-C gap")
            hid = next(h["id"] for h in z["hosts"] if h["ip"] == ip)
            req.patch(self.base + f"/assets/{hid}?sl_c=none")
        # firewall SL-C from the devices card
        drow = page.locator("[data-testid=iec-dev-row]").first
        if drow.count():
            fid = drow.get_attribute("data-fw-id")
            drow.locator("[data-testid=iec-dev-slc]").select_option("2")
            # the select already reads "2" once picked, so wait for the save itself
            with page.expect_response(lambda r: "/sl-c" in r.url and r.request.method == "PATCH", timeout=15000):
                drow.locator("[data-testid=iec-dev-save]").click()
            page.wait_for_load_state("networkidle")
            dev = next(d for d in self.api(req, "/iec-conduits")["devices"] if str(d["id"]) == fid)
            self.check(dev["sl_c"] == 2, "[iec] firewall SL-C not saved")
            req.patch(self.base + f"/firewalls/{fid}/sl-c?site_id={self.cur_site}", data='{"sl_c": null}',
                      headers={"Content-Type": "application/json"})
        # export
        r = req.get(self.base + f"/iec-zones/export?table=assets&site_id={self.cur_site}")
        self.check(r.ok and "zone" in r.text().splitlines()[0], "[iec] assets export failed")
        after = fsum()
        self.check(after.get("by_check_name", {}).get("undocumented_conduit", 0) == len(pairs) or not pairs,
                   "[iec] undocumented_conduit count != pairs")
        strip = lambda d: {k: v for k, v in (d.get("by_check_name") or {}).items()
                           if k not in ("undocumented_conduit", "host_in_multiple_zones", "network_in_multiple_zones")}
        self.check(strip(after) == strip(before), "[iec] other findings changed after documenting zones")
        self.shot(page, "iec_zones")
        # clean up: delete both zones from the page / API
        page.locator(f'[data-testid=iec-zone-row][data-zone-id="{cell["id"]}"]').click() if not page.locator(
            f'[data-testid=iec-zone-panel][data-zone-id="{cell["id"]}"]').count() else None
        btn = page.locator(f'[data-testid=iec-zone-panel][data-zone-id="{cell["id"]}"] [data-testid=iec-edit-delete]')
        btn.click()
        btn.click()
        page.wait_for_function(f"() => !document.querySelector('[data-testid=iec-zone-row][data-zone-id=\"{cell['id']}\"]')", timeout=15000)
        req.delete(self.base + f"/iec-zones/{made[1]['id']}?site_id={self.cur_site}")
        self.check({z["id"] for z in self.api(req, "/iec-zones")["zones"]} == pre, "[iec] zones not removed")

    def s_extcomms(self, page, req):
        """RS G5: one row per flow /external-comms lists; Approve saves a
        review for that host and destination, Reset removes it."""
        d = self.api(req, "/external-comms")
        rows = d["flows"]
        self.check(page.locator("[data-testid=ec-row]").count() == len(rows), "[extcomms] row count != /external-comms")
        self.check(page.locator("[data-testid=ec-summary]").count() == 1, "[extcomms] summary missing")
        self.check(page.locator("[data-testid=ec-ot]").count() == sum(1 for r in rows if r.get("ot_host")),
                   "[extcomms] OT marker count != API ot_host rows")
        if not rows:
            return
        r0 = rows[0]
        src, dest = r0["inside"]["ip"], r0["dest_key"]
        sel = f'[data-testid=ec-row][data-src="{src}"][data-dest="{dest}"]'
        if r0["review"]:
            page.locator(f"{sel} [data-testid=ec-reset]").click()
            page.wait_for_selector(f"{sel} [data-testid=ec-approve]", timeout=15000)
        page.locator(f"{sel} [data-testid=ec-approve]").click()
        page.wait_for_selector(f"{sel} [data-testid=ec-reset]", timeout=15000)
        got = {(x["inside"]["ip"], x["dest_key"]): x for x in self.api(req, "/external-comms")["flows"]}[(src, dest)]
        self.check(got["status"] == "approved" and got["review"]["src"] == src, "[extcomms] approval not saved")
        self.check(page.locator(f"{sel} [data-testid=ec-st]").inner_text().strip() == "approved",
                   "[extcomms] row does not show approved")
        page.locator(f"{sel} [data-testid=ec-reset]").click()
        page.wait_for_selector(f"{sel} [data-testid=ec-approve]", timeout=15000)
        got = {(x["inside"]["ip"], x["dest_key"]): x for x in self.api(req, "/external-comms")["flows"]}[(src, dest)]
        self.check(got["review"] is None, "[extcomms] Reset did not remove the review")

    def s_mgmt(self, page, req):
        """Management networks: the page lists the site's interfaces / VLANs;
        a declaration from the form re-checks and shows up; Remove undoes it."""
        d = self.api(req, "/management/networks")
        self.check(page.locator("[data-testid=mgmt-interfaces]").count() == 1, "[mgmt] interfaces card missing")
        self.check(page.locator("[data-testid=mgmt-vlans]").count() == 1, "[mgmt] VLANs card missing")
        self.check(page.locator("[data-testid=mgmt-vpn-groups]").count() == 1, "[mgmt] VPN groups card missing")
        n_iface = len([i for i in d["interfaces"] if i["management_access"] or i["is_management"]
                       or i["purpose"] or i["declared"] is not None])
        self.check(page.locator("[data-testid=mgmt-interfaces] tbody tr").count() == n_iface,
                   "[mgmt] interface row count mismatch")
        page.locator("#mg-kind").select_option("vlan")
        page.locator("#mg-vlan").fill("3999")
        page.locator("#mg-purpose").select_option("engineering")
        page.locator("#mg-by").fill("smoke")
        page.locator("#mg-add").click()
        page.wait_for_selector("[data-testid=mgmt-recheck-result]", timeout=120000)
        decls = self.api(req, "/management/networks")["declarations"]
        mine = [x for x in decls if x["key"] == "vlan:3999"]
        self.check(len(mine) == 1 and mine[0]["created_by"] == "smoke"
                   and mine[0]["purpose"] == "engineering", "[mgmt] engineering declaration not saved")
        if mine:
            self.check(page.locator(f'tr[data-decl-id="{mine[0]["id"]}"][data-purpose="engineering"]').count() == 1,
                       "[mgmt] declaration row does not show its purpose")
        if mine:
            page.locator(f'tr[data-decl-id="{mine[0]["id"]}"] button').click()
            page.wait_for_function("() => !document.querySelector('tr[data-decl-id=\"%d\"]')" % mine[0]["id"],
                                   timeout=120000)
            left = [x for x in self.api(req, "/management/networks")["declarations"] if x["key"] == "vlan:3999"]
            self.check(not left, "[mgmt] Remove did not delete the declaration")

    def s_reach(self, page, req):
        data = self.api(req, "/reachability")
        m = data["matrix"]
        self.check(page.locator(".rcell[data-key]").count() == len(m), "[reach] cell count mismatch")
        counts = {}
        for c in m.values():
            counts[c["overall"]] = counts.get(c["overall"], 0) + 1
        for v in ["permitted", "denied", "partial", ""]:
            page.locator("#r-verdict").select_option(v)
            live = page.locator(".rcell[data-key]:not(.dimmed)").count()
            exp = len(m) if v == "" else counts.get(v, 0)
            self.check(live == exp, f"[reach] filter {v or 'all'}: {live} visible, expected {exp}")
        target = next((k for k, c in m.items() if c["overall"] == "partial"), None) or \
                 next((k for k, c in m.items() if c["paths"]), None)
        if self.check(target, "[reach] no cell with paths"):
            page.locator(f'.rcell[data-key="{target}"]').click()
            det = page.locator("#reach-cell-detail")
            det.wait_for()
            txt = det.inner_text()
            self.check("Path 1" in txt and ("partial_services" in txt or "matched_rule" in txt or "implicit_deny" in txt),
                       "[reach] cell detail lacks paths/reason codes")
            if m[target]["overall"] == "partial":
                self.check(all(s in txt for s in m[target]["permitted_services"]), "[reach] permitted services missing")
        # host path lookup between two classified hosts on different levels
        nodes = [n for n in self.api(req, "/topology")["nodes"] if n["ip"] and n["purdue_level"] is not None]
        src = next((n for n in nodes if n["purdue_level"] == 4), None)
        dst = next((n for n in nodes if n["purdue_level"] == 1), None)
        if src and dst:
            page.locator("#p-src").fill(src["ip"])
            page.locator("#p-dst").fill(dst["ip"])
            page.locator("#path-run").click()
            page.locator("#reach-path-detail").wait_for(timeout=10000)
            self.check("Boundary" in page.locator("#reach-path-detail").inner_text() or "no enforcement" in page.locator("#reach-path-detail").inner_text(),
                       "[reach] path lookup rendered no hops")
        # F-05: NAT on the host path lookup (VIP 10.0.2.80 on FW-OT -> 10.0.1.10)
        nat = [n for n in self.api(req, "/nat-rules") if n["nat_type"] == "dnat"]
        if self.check(nat, "[reach] seed has no DNAT rule"):
            vip_ip = nat[0]["ext_ip"].split("/")[0]
            jump = next((n for n in nodes if n["purdue_level"] == 3.5), None)
            if self.check(jump, "[reach] no L3.5 host for the NAT path"):
                api_r = self.api(req, f"/reachability/path?src={jump['ip']}&dst={vip_ip}&dst_port=22&protocol=tcp")
                page.locator("#p-src").fill(jump["ip"])
                page.locator("#p-dst").fill(vip_ip)
                page.locator("#p-port").fill("22")
                page.locator("#p-proto").select_option("tcp")
                page.locator("#path-run").click()
                det = page.locator("#reach-path-detail")
                det.wait_for(timeout=10000)
                txt = det.inner_text()
                nd = api_r.get("nat_destination")
                if self.check(nd, "[reach] API returned no nat_destination"):
                    self.check(det.locator("[data-testid=nat-destination]").count() == 1, "[reach] NAT destination row missing")
                    self.check(f"{nd['ext_ip']} → {nd['mapped_ip']}" in txt and nd["name"] in txt, "[reach] nat_destination not rendered")
                lines = det.locator(".nat-line")
                self.check(lines.count() == len(api_r["nat"]) and len(api_r["nat"]) > 0, f"[reach] path NAT lines {lines.count()} != {len(api_r['nat'])}")
                for n in api_r["nat"]:
                    o, t2 = n["original"], n["translated"]
                    self.check(f"{o['dst_ip']}:{o['dst_port']} → {t2['dst_ip']}:{t2['dst_port']}" in txt, "[reach] NAT original → translated missing")
                    self.check(("post-NAT" if n["policy_evaluated_on"] == "post_nat" else "pre-NAT") in txt, "[reach] policy_evaluated_on missing")
                self.shot(page, "reach_path_nat")
                # matrix with the same host pair: the cell detail shows NAT on its paths
                page.locator("#r-src-ip").fill(jump["ip"])
                page.locator("#r-dst-ip").fill(vip_ip)
                page.locator("#reach-run").click()
                page.wait_for_load_state("networkidle")
                m2 = self.api(req, f"/reachability?src_ip={jump['ip']}&dst_ip={vip_ip}")["matrix"]
                key = next((k for k, c in m2.items() if any(p.get("nat") for p in c["paths"])), None)
                if self.check(key, "[reach] matrix with NAT filter has no NAT path"):
                    page.locator(f'.rcell[data-key="{key}"]').click()
                    cd = page.locator("#reach-cell-detail")
                    cd.wait_for()
                    want = sum(len(p.get("nat") or []) for p in m2[key]["paths"])
                    self.check(cd.locator(".nat-line").count() == want, f"[reach] cell NAT lines {cd.locator('.nat-line').count()} != {want}")
                    self.check("NAT ×" in cd.inner_text(), "[reach] path NAT chip missing")
                    self.shot(page, "reach_cell_nat")
                page.locator("#r-src-ip").fill("")
                page.locator("#r-dst-ip").fill("")
                page.locator("#reach-run").click()
                page.wait_for_load_state("networkidle")
        page.locator(f'.rcell[data-key="{target}"]').click()

    # -------------------------------------------------------- access review
    def ar_row(self, key):
        return f'#ar-main tr.ar-row[data-tag-key="{key}"]'

    def ar_post(self, page, action):
        """Run action() and wait for its POST /access-paths/classify + re-render."""
        with page.expect_response(lambda r: "/access-paths/classify" in r.url and r.request.method == "POST", timeout=15000) as ri:
            action()
        resp = ri.value
        self.check(resp.status == 200, f"[accessreview] classify POST -> {resp.status}")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(150)
        return resp.json() if resp.status == 200 else {}

    def ar_wait_rows(self, page, n):
        try:
            page.wait_for_function("(n) => document.querySelectorAll('#ar-paths-table tr.ar-row').length === n", arg=n, timeout=15000)
        except Exception:  # noqa: BLE001 - the caller's check reports the mismatch
            pass
        page.wait_for_load_state("networkidle")

    def ar_report_count(self, page):
        txt = page.locator("#ar-report").inner_text()
        m = re.search(r"Generate report \((\d+) lines?\)", txt)
        return int(m.group(1)) if m else None

    def ar_hops_nowrap(self, page, scope, tag):
        """Hop / Firewall / VDOM / Policy / Action cells of the path-detail hop
        table are on one line; Name wraps at word boundaries only."""
        info = page.evaluate("""(sel) => {
          const t = document.querySelector(sel + ' [data-testid=ar-hops]');
          if (!t) return null;
          const lines = (td) => { const r = document.createRange(); r.selectNodeContents(td);
            return new Set([...r.getClientRects()].map(x => Math.round(x.top))).size; };
          const rows = [...t.tBodies[0].rows].map(tr => [...tr.cells].map(td => ({
            text: td.textContent, lines: lines(td), ws: getComputedStyle(td).whiteSpace,
            wb: getComputedStyle(td).wordBreak, ow: getComputedStyle(td).overflowWrap })));
          return rows;
        }""", scope)
        if not self.check(bool(info), f"{tag} no hop table in the path detail"):
            return
        for row in info:
            for i in (0, 1, 2, 3, 5):
                c = row[i]
                self.check(c["ws"] == "nowrap" and c["lines"] == 1, f"{tag} hop cell {c['text']!r} wraps ({c['lines']} lines, {c['ws']})")
            name = row[4]
            self.check(name["wb"] == "normal" and name["ow"] == "normal", f"{tag} hop Name cell may break inside words ({name['wb']}/{name['ow']})")

    def ar_bulk_note(self, page, req, k1, k2):
        """Bulk bar note: Apply carries the typed note to every selected row
        (replacing a different note only after a confirm); Set note alone;
        a dismissed confirm saves nothing."""
        cur = lambda: {p_["tag_key"]: p_ for p_ in self.api(req, "/access-paths")["paths"]}
        fp = "False positive: vendor link <img src=x onerror=window.__xss=1>"
        page.locator("#ar-bulk-note").fill(fp)
        page.locator("#ar-bulk-by").fill("smoke-bulk")
        page.locator("#ar-bulk-cls").select_option("reviewed_ok")
        dialogs = []
        page.once("dialog", lambda d: (dialogs.append(d.message), d.accept()))
        res = self.ar_post(page, lambda: page.locator("#ar-bulk-apply").click())
        self.check(dialogs and "1 of the 2 selected rows" in dialogs[0], f"[ar_bulk_note] no replace confirm: {dialogs}")
        self.check(all(i.get("note") == fp for i in res.get("items", [])) and len(res.get("items", [])) == 2,
                   "[ar_bulk_note] Apply did not carry the note to both rows")
        c = cur()
        self.check(all(c[k]["classification"] == "reviewed_ok" and c[k]["note"] == fp and c[k]["classified_by"] == "smoke-bulk"
                       for k in (k1, k2)), f"[ar_bulk_note] not persisted: {[(c[k]['classification'], c[k]['note'], c[k]['classified_by']) for k in (k1, k2)]}")
        self.check(page.locator("#ar-bulk-note").input_value() == "", "[ar_bulk_note] note box not cleared after saving")
        self.check("with the note" in page.locator("#ar-bulk-msg").inner_text(), "[ar_bulk_note] result line does not mention the note")
        # Set note: dismissing the confirm saves nothing
        page.locator("#ar-bulk-note").fill("ticket CHG-42")
        page.once("dialog", lambda d: d.dismiss())
        page.locator("#ar-bulk-note-set").click()
        page.wait_for_timeout(300)
        self.check("Nothing saved" in page.locator("#ar-bulk-msg").inner_text() and cur()[k1]["note"] == fp,
                   "[ar_bulk_note] dismissed confirm still saved")
        page.once("dialog", lambda d: d.accept())
        self.ar_post(page, lambda: page.locator("#ar-bulk-note-set").click())
        c = cur()
        self.check(c[k1]["note"] == "ticket CHG-42" and c[k2]["note"] == "ticket CHG-42"
                   and c[k1]["classification"] == "reviewed_ok", "[ar_bulk_note] Set note not persisted (or classification changed)")

    def s_accessreview(self, page, req):
        d = self.api(req, "/access-paths")
        paths, flows = d["paths"], d.get("unmatched_observed") or []
        # 2026-10-19: the tunnel_selector flag has a filter checkbox and the seeded FW-LINK row carries it
        self.check(page.locator("[data-testid=ar-flag-tunnel_selector]").count() == 1, "[accessreview] tunnel_selector flag filter missing")
        self.check(any("tunnel_selector" in (r.get("flags") or []) for r in paths), "[accessreview] no tunnel_selector row in the seed")
        # the per-row checks below need one tr.ar-row per path: roll-up off (default on)
        self.check(page.locator("#ar-f-rollup").is_checked(), "[accessreview] roll-up is not on by default")
        page.locator("#ar-f-rollup").uncheck()
        page.wait_for_timeout(150)
        rows = page.locator("#ar-paths-table tr.ar-row")
        self.check(len(paths) > 0, "[accessreview] seed has no access paths")
        self.check(rows.count() == len(paths), f"[accessreview] {rows.count()} path rows, API has {len(paths)}")
        self.check(page.locator("#ar-flows-table tr.ar-row").count() == len(flows) and len(flows) >= 1,
                   f"[accessreview] unexplained flow rows != API ({len(flows)})")
        self.check(any(p["flags"] for p in paths) and page.locator("#ar-paths-table .ar-flag").count() >= 1, "[accessreview] no flagged row shown")
        self.check(any(p["classification"] != "unclassified" for p in paths + flows), "[accessreview] seed has no classified row")
        summ = page.locator("#ar-summary").inner_text()
        self.check(f"{len(paths)} allowed path" in summ and "seen in capture" in summ and "unexplained flow" in summ,
                   f"[accessreview] summary line: {summ!r}")
        # Generate report: count + link
        self.check(self.ar_report_count(page) == d["counts"]["report_include"],
                   f"[accessreview] report button {page.locator('#ar-report').inner_text()!r} != counts.report_include {d['counts']['report_include']}")
        # counts.report_include = every line the report prints (paths + composed + unexplained)
        bk = d["counts"].get("report_include_by_kind") or {}
        self.check(set(bk) == {"path", "composed", "unexplained"} and sum(bk.values()) == d["counts"]["report_include"],
                   f"[accessreview] report_include {d['counts']['report_include']} != by_kind {bk}")
        if not d.get("unmatched_capped"):
            n_flows = sum(1 for f in flows if f.get("report_include"))
            self.check(bk.get("unexplained") == n_flows, f"[accessreview] by_kind.unexplained {bk.get('unexplained')} != included flows {n_flows}")
            n_comp = sum(1 for p_ in paths if p_.get("report_include") and p_["direction"] == "composed")
            self.check(bk.get("composed") == n_comp, f"[accessreview] by_kind.composed {bk.get('composed')} != included composed rows {n_comp}")
        # declared hops panel: summary matches GET /access-paths/hops; a bad
        # declaration is refused inline (422) without changing anything
        hp = self.api(req, "/access-paths/hops")
        self.check(page.locator("#ar-hops-panel").count() == 1, "[accessreview] declared-hops panel missing")
        sm = page.locator("#ar-hops-summary").inner_text()
        parts = [x.strip() for x in sm.split("·")[1:]]
        want = ([f"{len(hp['hops'])} declared"] if hp["hops"] else []) + \
               ([f"{len(hp['suggestions'])} suggested"] if hp["suggestions"] else [])
        self.check(parts == want, f"[accessreview] hops summary {sm!r} vs API {want}")
        self.check(page.locator("[data-testid=ar-hops-table] tbody tr").count() == len(hp["hops"]),
                   f"[accessreview] hops table rows != API ({len(hp['hops'])})")
        self.check(page.locator("[data-testid=ar-hop-suggestion]").count() == len(hp["suggestions"]),
                   f"[accessreview] suggestion rows != API ({len(hp['suggestions'])})")
        self.check(page.locator("[data-testid=ar-hops-error]").count() == 0, "[accessreview] hops error shown although GET succeeded")
        hop_rows = [p_ for p_ in paths if p_.get("hop")]
        for p_ in hop_rows[:3]:
            self.check("(declared hop)" in page.locator(self.ar_row(p_["tag_key"])).inner_text(),
                       f"[accessreview] {p_['tag_key']}: declared hop not shown on the row")
        page.locator("#ar-hops-panel summary").click()
        self.allowed.append("/access-paths/hops")
        page.fill("#ar-hop-from", "203.0.113.1")
        page.fill("#ar-hop-to", "203.0.113.2")
        with page.expect_response(lambda r: "/access-paths/hops" in r.url and r.request.method == "POST", timeout=15000) as ri:
            page.click("#ar-hop-add")
        self.check(ri.value.status == 422, f"[accessreview] unknown-host hop POST -> {ri.value.status}")
        page.wait_for_function("() => document.getElementById('ar-hop-msg').textContent.startsWith('Not saved')", timeout=5000)
        self.check(len(self.api(req, "/access-paths/hops")["hops"]) == len(hp["hops"]), "[accessreview] refused hop changed the list")
        href = page.locator("#ar-report").get_attribute("href") or ""
        u = urllib.parse.urlparse(href)
        self.check(u.path == "/reports/compliance.pdf" and u.query == f"site_id={self.cur_site}"
                   and page.locator("#ar-report").get_attribute("target") == "_blank", f"[accessreview] report link {href}")
        # traffic wording
        txt = page.locator("#ar-paths-table").inner_text()
        for p_ in paths:
            st = p_["traffic"]["status"]
            want = {"seen": "Seen in capture", "not_seen": "Not seen in capture", "no_capture": "No capture loaded", "partial": "Seen on one leg"}[st]
            self.check(want in page.locator(self.ar_row(p_["tag_key"])).inner_text(), f"[accessreview] {p_['tag_key']}: traffic wording {want!r} missing")
        # client-side filters
        up = d["counts"]["by_direction"].get("up", 0)
        page.locator("[data-testid=ar-dir-up]").check()
        self.check(rows.count() == up, f"[accessreview] uphill filter: {rows.count()} rows, API {up}")
        page.locator("[data-testid=ar-dir-all]").check()
        flag = next(iter(d["counts"]["by_flag"]))
        page.locator(f"[data-testid=ar-flag-{flag}]").check()
        self.check(rows.count() == d["counts"]["by_flag"][flag], f"[accessreview] flag filter {flag}: {rows.count()} rows")
        page.locator(f"[data-testid=ar-flag-{flag}]").uncheck()
        wide = self.api(req, "/access-paths?boundary_only=false")
        with page.expect_response(lambda r: "/access-paths?" in r.url and "boundary_only=false" in r.url):
            page.locator("#ar-f-boundary").uncheck()
        self.ar_wait_rows(page, len(wide["paths"]))
        self.check(rows.count() == len(wide["paths"]), f"[accessreview] boundary_only=false: {rows.count()} rows, API {len(wide['paths'])}")
        with page.expect_response(lambda r: "/access-paths?" in r.url and "boundary_only=true" in r.url):
            page.locator("#ar-f-boundary").check()
        self.ar_wait_rows(page, len(paths))
        self.check(rows.count() == len(paths), "[accessreview] cross-boundary re-query did not restore the rows")

        uncls = [p_ for p_ in paths if p_["classification"] == "unclassified"]
        if not self.check(len(uncls) >= 2, "[accessreview] need two unclassified paths"):
            return
        k1, k2 = uncls[0]["tag_key"], uncls[1]["tag_key"]
        # expand a row, set the remembered "classified by", then classify via the select
        page.locator(f"{self.ar_row(k1)} .ar-exp").click()
        page.locator("#ar-main tr.ar-detail .ar-by").fill("smoke-reviewer")
        stored = page.evaluate("() => { try { return localStorage.getItem('iasc_ar_classified_by'); } catch (e) { return null; } }")
        self.check(stored == "smoke-reviewer", f"[accessreview] classified-by not remembered ({stored!r})")
        self.ar_post(page, lambda: page.locator(f"{self.ar_row(k1)} .ar-cls").select_option("permissive"))
        got = next(p_ for p_ in self.api(req, "/access-paths")["paths"] if p_["tag_key"] == k1)
        self.check(got["classification"] == "permissive" and got["classified_by"] == "smoke-reviewer",
                   f"[accessreview] select classification not persisted: {got['classification']} / {got['classified_by']}")
        self.check(page.locator(f"{self.ar_row(k1)} .ar-cls").input_value() == "permissive", "[accessreview] select not refreshed from the response")
        self.check("by smoke-reviewer" in page.locator(f'#ar-main tr.ar-detail[data-tag-key="{k1}"]').inner_text(),
                   "[accessreview] 'classified <by> · <at>' not shown")
        # save a reviewer note in the expanded row
        note = 'Smoke note <b>not bold</b> & "quoted"'
        page.locator(f'#ar-main tr.ar-detail[data-tag-key="{k1}"] .ar-note').fill(note)
        self.ar_post(page, lambda: page.locator(f'#ar-main tr.ar-detail[data-tag-key="{k1}"] .ar-note-save').click())
        got = next(p_ for p_ in self.api(req, "/access-paths")["paths"] if p_["tag_key"] == k1)
        self.check(got["note"] == note, f"[accessreview] note not persisted: {got['note']!r}")
        self.check("Note saved" in page.locator(f'#ar-main tr.ar-detail[data-tag-key="{k1}"]').inner_text(), "[accessreview] note save not confirmed")
        # toggle "In report"
        before = next(p_ for p_ in self.api(req, "/access-paths")["paths"] if p_["tag_key"] == k2)["report_include"]
        self.ar_post(page, lambda: page.locator(f"{self.ar_row(k2)} .ar-inc").click())
        after = next(p_ for p_ in self.api(req, "/access-paths")["paths"] if p_["tag_key"] == k2)["report_include"]
        self.check(after is (not before), f"[accessreview] In report toggle not persisted ({before} -> {after})")
        self.check(page.locator(f"{self.ar_row(k2)} .ar-inc").is_checked() == after, "[accessreview] In report box not refreshed")
        # bulk-classify two rows
        page.locator(f"{self.ar_row(k1)} .ar-sel").check()
        page.locator(f"{self.ar_row(k2)} .ar-sel").check()
        self.check(page.locator("#ar-bulk").is_visible() and "2 selected" in page.locator("#ar-bulk-count").inner_text(),
                   "[accessreview] bulk bar not shown with 2 selected")
        page.locator("#ar-bulk-cls").select_option("exception")
        res = self.ar_post(page, lambda: page.locator("#ar-bulk-apply").click())
        self.check(len(res.get("items", [])) == 2, "[accessreview] bulk POST did not carry both rows")
        cur = {p_["tag_key"]: p_ for p_ in self.api(req, "/access-paths")["paths"]}
        self.check(cur[k1]["classification"] == "exception" and cur[k2]["classification"] == "exception",
                   "[accessreview] bulk classification not persisted")
        self.check("2 rows" in page.locator("#ar-bulk-msg").inner_text(), f"[accessreview] bulk result not shown: {page.locator('#ar-bulk-msg').inner_text()!r}")
        self.check(page.locator(f"{self.ar_row(k1)} .ar-sel").is_checked() and page.locator(f"{self.ar_row(k2)} .ar-sel").is_checked(),
                   "[accessreview] selection lost after the bulk action")
        self.ar_bulk_note(page, req, k1, k2)
        page.locator("#ar-bulk-clear").click()
        self.check(page.locator("#ar-bulk").is_hidden(), "[accessreview] bulk bar still shown after Clear selection")
        # Generate report count follows the stored state
        d2 = self.api(req, "/access-paths")
        self.check(self.ar_report_count(page) == d2["counts"]["report_include"],
                   f"[accessreview] report button {self.ar_report_count(page)} != counts.report_include {d2['counts']['report_include']} after edits")
        # keyboard: Tab from a row's checkbox to its expander, Enter opens it; a sort header
        page.locator(f"{self.ar_row(k1)} .ar-exp").click()     # close the open detail first
        self.check(page.locator(f'#ar-main tr.ar-detail[data-tag-key="{k1}"]').count() == 0, "[accessreview] expander did not close the row")
        page.locator(f"{self.ar_row(k2)} .ar-sel").focus()
        page.keyboard.press("Tab")
        on_exp = page.evaluate("() => document.activeElement && document.activeElement.classList.contains('ar-exp')")
        if self.check(on_exp, "[accessreview] Tab from the row checkbox did not reach the row expander"):
            outline = page.evaluate("() => getComputedStyle(document.activeElement).outlineStyle")
            self.check(outline not in ("none", ""), f"[accessreview] no visible focus outline on the expander ({outline})")
            page.keyboard.press("Enter")
            page.wait_for_timeout(150)
            self.check(page.locator(f'#ar-main tr.ar-detail[data-tag-key="{k2}"]').count() == 1
                       and page.locator(f"{self.ar_row(k2)} .ar-exp").get_attribute("aria-expanded") == "true",
                       "[accessreview] Enter on the expander did not open the row")
            self.check(page.evaluate("() => document.activeElement && document.activeElement.classList.contains('ar-exp')"),
                       "[accessreview] focus lost after opening a row")
            txt = page.locator(f'#ar-main tr.ar-detail[data-tag-key="{k2}"]').text_content()
            self.check("Path detail" in txt and "Why flagged" in txt and "Traffic evidence" in txt, "[accessreview] detail sections missing")
            for f in cur[k2]["flags"]:
                self.check(f in txt, f"[accessreview] flag {f} not explained in the detail")
            self.ar_hops_nowrap(page, f'#ar-main tr.ar-detail[data-tag-key="{k2}"]', "[accessreview]")
        page.locator('#ar-paths-table .th-btn[data-sort="src"]').focus()
        page.keyboard.press("Enter")
        self.check(page.locator('#ar-paths-table th:has(.th-btn[data-sort="src"])').get_attribute("aria-sort") == "ascending",
                   "[accessreview] sort header not operable from the keyboard")
        self.check(page.evaluate("() => document.activeElement && document.activeElement.dataset.sort === 'src'"), "[accessreview] focus lost after sorting")
        # toggling an unexplained flow's "In report" moves the Generate report count
        if flows:
            fk = flows[0]["tag_key"]
            n0 = self.ar_report_count(page)
            was = page.locator(f"{self.ar_row(fk)} .ar-inc").is_checked()
            res = self.ar_post(page, lambda: page.locator(f"{self.ar_row(fk)} .ar-inc").click())
            d3 = self.api(req, "/access-paths")
            self.check(self.ar_report_count(page) == d3["counts"]["report_include"] == (res.get("counts") or {}).get("report_include")
                       and self.ar_report_count(page) == (n0 or 0) + (-1 if was else 1),
                       f"[accessreview] flow In report toggle: button {n0} -> {self.ar_report_count(page)}, API {d3['counts']['report_include']}")
            self.ar_post(page, lambda: page.locator(f"{self.ar_row(fk)} .ar-inc").click())
            self.check(self.ar_report_count(page) == n0, f"[accessreview] report count not restored ({self.ar_report_count(page)} != {n0})")
        # the planted XSS in the seeded flow's note / classified_by renders as text
        if flows:
            fk = flows[0]["tag_key"]
            page.locator(f"{self.ar_row(fk)} .ar-exp").click()
            det = page.locator(f'#ar-main tr.ar-detail[data-tag-key="{fk}"]')
            self.check("data-xss" in det.inner_text() or "data-xss" in det.locator(".ar-note").input_value(),
                       "[accessreview] seeded flow note / classified_by not rendered as text")
        self.shot(page, "accessreview_detail")
        # never "unused" on this page (a capture is a sample)
        text = page.evaluate("() => document.getElementById('page-accessreview').textContent")
        self.check("unused" not in text.lower(), "[accessreview] page text contains 'unused'")
        self.ar_rollup(page, req)

    def ar_rollup(self, page, req):
        """Roll-up: rows differing only in the destination (or source) host are
        one tr.ar-group line whose count, members, select, classification and
        report checkbox follow the API rows (app/parsers/access_path_groups)."""
        sys.path.insert(0, str(ROOT))
        from app.parsers.access_path_groups import roll_up
        paths = self.api(req, "/access-paths")["paths"]
        self.check(all(p_.get("group_dst") and p_.get("group_src") for p_ in paths), "[rollup] API rows lack group keys")
        self.allowed.append("/access-paths/classify")
        page.locator("#ar-f-rollup").check()
        page.wait_for_timeout(200)
        lines = roll_up(paths)
        groups = [g for g in lines if g["vary"]]
        singles = [g for g in lines if not g["vary"]]
        self.check(page.locator("#ar-paths-table tr.ar-group").count() == len(groups), f"[rollup] {page.locator('#ar-paths-table tr.ar-group').count()} group lines, expected {len(groups)}")
        self.check(page.locator("#ar-paths-table tr.ar-row").count() == len(singles), "[rollup] collapsed groups still list their rows")
        head = page.locator("#ar-paths .ar-card-head").inner_text()
        if groups:
            self.check(f"rolled into {len(lines)} line" in head and f"({len(groups)} group" in head, f"[rollup] card head {head!r}")
        else:
            self.check("rolled into" not in head, f"[rollup] card head claims a roll-up with no group: {head!r}")
            return
        g = groups[0]
        sel = f'tr.ar-group[data-group-key="{g["key"]}"]'
        row = page.locator(sel)
        self.check(row.get_attribute("data-members") == str(len(g["rows"])), "[rollup] member count attribute")
        n_scopes = len(g["scopes"]) or len(g["rows"])
        what = "destination" if g["vary"] == "dst" else "source"
        self.check(page.locator(f"{sel} [data-testid=ar-group-count]").inner_text() == f"{n_scopes} {what}{'' if n_scopes == 1 else 's'}", "[rollup] group count text")
        for s in g["scopes"][:2]:
            self.check(s in row.inner_text(), f"[rollup] address {s} not listed on the group line")
        # traffic counts per status
        from collections import Counter
        st = Counter(((r.get("traffic") or {}).get("status") or "no_capture") for r in g["rows"])
        for k, n in st.items():
            self.check(f"×{n}" in row.locator(f".ar-tr-{k}").inner_text(), f"[rollup] traffic badge {k} ×{n} missing")
        # expand: the member rows appear, each a normal row
        page.locator(f"{sel} .ar-exp").click()
        page.wait_for_timeout(150)
        members = page.locator("#ar-paths-table tr.ar-member")
        self.check(members.count() == len(g["rows"]), f"[rollup] {members.count()} member rows shown, expected {len(g['rows'])}")
        for r in g["rows"]:
            self.check(page.locator(self.ar_row(r["tag_key"])).count() == 1, f"[rollup] member {r['tag_key']} missing after expanding")
        # the group checkbox selects every member; the bulk bar counts them
        page.locator(f"{sel} .ar-gsel").check()
        page.wait_for_timeout(150)
        self.check(page.locator("#ar-paths-table tr.ar-member .ar-sel:checked").count() == len(g["rows"]), "[rollup] group select did not select the members")
        self.check(not page.locator("#ar-bulk").is_hidden() and str(len(g["rows"])) in page.locator("#ar-bulk").inner_text(), "[rollup] bulk bar does not count the selected members")
        page.locator(f"{sel} .ar-gsel").uncheck()
        page.wait_for_timeout(150)
        self.check(page.locator("#ar-paths-table tr.ar-member .ar-sel:checked").count() == 0, "[rollup] group unselect left members selected")
        # classification on the group line applies to every member (and back)
        before = {r["tag_key"]: r["classification"] for r in g["rows"]}
        mixed = len(set(before.values())) > 1
        self.check((page.locator(f"{sel} .ar-gcls").input_value() == "") == mixed, "[rollup] group classification select does not reflect mixed / uniform members")
        target = "reviewed_ok" if "reviewed_ok" not in before.values() or mixed else "exception"
        self.ar_post(page, lambda: page.locator(f"{sel} .ar-gcls").select_option(target))
        after = {p_["tag_key"]: p_["classification"] for p_ in self.api(req, "/access-paths")["paths"]}
        self.check(all(after[k] == target for k in before), f"[rollup] group classification not applied to every member: {[after[k] for k in before]}")
        self.check(page.locator(f"{sel} .ar-gcls").input_value() == target, "[rollup] group select not showing the new value")
        items = [{"tag_key": k, "classification": v} for k, v in before.items()]
        r = req.post(self.base + "/access-paths/classify", data={"site_id": self.cur_site, "items": items})
        self.check(r.status == 200, f"[rollup] restore classification -> {r.status}")
        page.locator("#ar-f-rollup").uncheck()
        page.wait_for_timeout(150)
        page.locator("#ar-f-rollup").check()
        page.wait_for_timeout(150)
        self.shot(page, "accessreview_rollup")

    def s_shadow(self, page, req):
        # The seed's shadowed rules are on Plant B's Cisco firewall: analyse that site.
        a_id, b_id = self.site_id(req, "plant-a"), self.site_id(req, "plant-b")
        page.locator("#site-select").select_option(str(b_id))
        self.cur_site = b_id
        try:
            self.goto(page, "shadow")
            self._shadow_checks(page, req)
        finally:
            page.locator("#site-select").select_option(str(a_id))
            self.cur_site = a_id
            page.wait_for_load_state("networkidle")

    def _shadow_checks(self, page, req):
        d = self.api(req, "/firewall-rules/shadowed")
        self.check(len(d["shadows"]) > 0, "[shadow] seed has no shadows")
        # default: one card per policy pair; the cards account for every row pair
        pol = page.locator("#sh-policy")
        if not pol.is_checked():
            pol.check()
        groups = page.locator("#shadow-list-wrap > [data-testid=shadow-group]")
        plain = page.locator("#shadow-list-wrap > .shadow-row")
        n_pairs = sum(int(groups.nth(i).get_attribute("data-pairs")) for i in range(groups.count())) + plain.count()
        self.check(n_pairs == len(d["shadows"]), f"[shadow] policy cards cover {n_pairs} row pairs, API has {len(d['shadows'])}")
        if groups.count():
            g0 = groups.first
            g0.locator("[data-testid=shadow-expand]").click()
            want = int(g0.get_attribute("data-pairs"))
            self.check(g0.locator("[data-testid=shadow-pairs] .shadow-row").count() == want, "[shadow] expanded row pairs != card count")
            self.check(g0.locator("[data-testid=shadow-expand]").get_attribute("aria-expanded") == "true", "[shadow] expand button state")
            g0.locator("[data-testid=shadow-expand]").click()
        # one card per row pair when unticked
        pol.uncheck()
        self.check(page.locator("#shadow-list-wrap > .shadow-row").count() == len(d["shadows"]), "[shadow] row count mismatch (one card per row pair)")
        self.check(page.locator("[data-testid=shadow-group]").count() == 0, "[shadow] policy cards still shown after unticking")
        pol.check()
        txt = page.locator("#shadow-list-wrap").inner_text()
        for s in d["shadows"]:
            self.check(s["shadow_type"].replace("_", " ") in txt, f"[shadow] type {s['shadow_type']} not shown")
        n_boxes = page.locator("#shadow-list-wrap .shadow-rule:visible").count()
        self.check(txt.lower().count("last matched") == n_boxes, "[shadow] last matched missing from rule boxes")

    def s_attest(self, page, req):
        self.check(page.locator("#attest-rows .attest-card").count() == 6, "[attest] expected 6 checklist rows")
        before = [a for a in self.api(req, "/attestation") if a["checklist_id"] == "1.2"]
        plant_a = self.site_id(req, "plant-a")
        # multi-site: no site -> refused before any request
        page.locator("#att-site").select_option("")
        page.locator("#att-by").fill("smoke-no-site")
        page.locator("#att-submit").click()
        page.wait_for_function("() => /Choose the site/.test(document.getElementById('att-msg').textContent)", timeout=5000)
        page.locator("#att-site").select_option(str(plant_a))
        for i in (1, 2):
            page.locator("#att-row").select_option("1.2")
            page.locator("#att-baseline").select_option("")
            page.locator("#att-by").fill(f"smoke-tester-{i}")
            page.locator("#att-notes").fill(f"smoke attestation {i}")
            page.locator("#att-proof").set_input_files({"name": f"evidence{i}.txt", "mimeType": "text/plain", "buffer": b"evidence"})
            # clear the status line so the wait below sees THIS save, not the previous one
            page.evaluate("() => { document.getElementById('att-msg').textContent = ''; }")
            page.locator("#att-submit").click()
            page.wait_for_function("() => /Saved attestation/.test(document.getElementById('att-msg').textContent)", timeout=10000)
            page.wait_for_load_state("networkidle")
        recs = [a for a in self.api(req, "/attestation") if a["checklist_id"] == "1.2"]
        cur = [a for a in recs if a["is_current"] and a["baseline_id"] is None]
        self.check(len(recs) == len(before) + 2, "[attest] two new records not stored")
        self.check(len(cur) == 1 and cur[0]["attested_by"] == "smoke-tester-2", "[attest] second save did not demote the first")
        self.check(all(a["site_id"] == plant_a for a in recs[len(before):] if a["attested_by"].startswith("smoke-tester")),
                   "[attest] attestations not stored in the chosen site")
        try:
            page.wait_for_selector("#attest-history tr.superseded", timeout=10000)
        except Exception:
            pass
        self.check(page.locator("#attest-history tr.superseded").count() >= 1, "[attest] superseded record not shown in history")
        self.check(page.locator('#attest-rows .attest-card[data-row="1.2"] .status-pill.ok').count() == 1, "[attest] row 1.2 not shown as attested")
        self.check(page.locator("#attest-history a.proof-link").count() >= 2, "[attest] proof download links missing")
        # error path: unknown baseline -> API 404 detail must be shown
        self.allowed.append("/attestation")
        page.evaluate("() => { const s = document.getElementById('att-baseline'); const o = document.createElement('option'); o.value = 'NO-SUCH-BASELINE'; o.textContent = 'x'; s.append(o); s.value = 'NO-SUCH-BASELINE'; }")
        page.locator("#att-by").fill("smoke-error")
        page.locator("#att-submit").click()
        page.wait_for_function("() => /HTTP 404/.test(document.getElementById('att-msg').textContent)", timeout=10000)
        self.check("not found" in page.locator("#att-msg").inner_text(), "[attest] 404 detail not surfaced")
        page.locator("#att-baseline").select_option("")

    def assets_exclude(self, page, req):
        """Owner 2026-10-14: exclude a host from the inventory (reason + name) - it leaves the list,
        shows under the Excluded filter with a badge, and can be included again."""
        row = page.locator("#assets-tbody tr").first
        ip = row.locator("td").first.inner_text().strip()
        row.click()
        page.wait_for_selector("[data-testid=asset-exclude]", timeout=10000)
        page.locator("[data-testid=asset-excl-reason]").fill("smoke: visitor <img src=x onerror=window.__xss=1>")
        page.locator("[data-testid=asset-excl-by]").fill("smoke")
        page.locator("[data-testid=asset-exclude]").click()
        page.wait_for_function("(ip) => ![...document.querySelectorAll('#assets-tbody tr td:first-child')].some(td => td.textContent.trim() === ip)", arg=ip, timeout=15000)
        site = self.api(req, "/firewall-rules")[0]["site_id"]
        ex = [a for a in self.api_all(req, f"/assets?site_id={site}&inventory=excluded&limit=10000") if a["ip"] == ip]
        self.check(len(ex) == 1 and ex[0]["inventory_excluded_by"] == "smoke", "[assets_exclude] exclusion not stored")
        self.check(ip not in [a["ip"] for a in self.api_all(req, f"/assets?site_id={site}&limit=10000")], "[assets_exclude] still listed by default")
        page.locator("#a-inv").select_option("excluded")
        page.wait_for_selector("[data-testid=asset-excluded]", timeout=10000)
        self.check(page.locator("#assets-tbody tr").count() == 1, "[assets_exclude] Excluded filter shows more than the excluded host")
        page.locator("#assets-tbody tr").first.click()
        page.wait_for_selector("[data-testid=asset-include]", timeout=10000)
        self.shot(page, "assets_exclude")
        page.locator("[data-testid=asset-include]").click()
        page.wait_for_function("() => document.querySelectorAll('[data-testid=asset-excluded]').length === 0", timeout=15000)
        page.locator("#a-inv").select_option("")
        page.wait_for_function("(ip) => [...document.querySelectorAll('#assets-tbody tr td:first-child')].some(td => td.textContent.trim() === ip)", arg=ip, timeout=15000)

    def s_assets(self, page, req):
        assets = self.api(req, "/assets")
        self.check(page.locator("#assets-tbody tr").count() == len(assets), "[assets] row count mismatch")
        self.assets_exclude(page, req)
        heads = page.locator("#assets-thead th").all_inner_texts()
        # owner 2026-10-13: Zone = the IEC 62443 zone (the API returns iec_zone / iec_zones)
        self.check(any(h.startswith("Zone") for h in heads) and all("iec_zones" in x for x in assets),
                   "[assets] Zone column / iec_zones missing")
        # owner 2026-10-13: a clicked row stays where it is (selected in place, no
        # jump to the top), also when the list reloads
        rows = page.locator("#assets-tbody tr")
        rows.first.click()
        last = rows.nth(rows.count() - 1)
        last.scroll_into_view_if_needed()
        y0 = last.bounding_box()["y"]
        last.click()
        page.wait_for_timeout(200)
        self.check(abs(last.bounding_box()["y"] - y0) < 2 and "selected" in (last.get_attribute("class") or ""),
                   "[assets] clicked row moved on the screen")
        page.evaluate("() => loadAssets()")
        page.wait_for_load_state("networkidle")
        sel = page.locator("#assets-tbody tr.selected")
        self.check(sel.count() == 1 and abs(sel.bounding_box()["y"] - y0) < 2, "[assets] selected row moved after a reload")
        target = assets[0]
        page.locator(f'#assets-tbody tr[data-asset-id="{target["id"]}"]').click()
        self.check(page.locator("#ae-hostname").count() == 0, "[assets] hostname still editable")
        self.check(page.locator("[data-testid=ae-zone]").count() == 1, "[assets] IEC zone field missing")
        opts = page.locator("#ae-criticality option").all_inner_texts()
        self.check(not any(o.lower() == "critical" for o in opts), "[assets] 'critical' criticality offered")
        owner = f"smoke-owner-{int(time.time())}"
        crit = "medium" if target.get("criticality") == "high" else "high"
        page.locator("#ae-owner").fill(owner)
        page.locator("#ae-criticality").select_option(crit)
        page.locator("#ae-location").fill("Plant A")   # B-24: free-text location (asset field "site")
        page.locator("#ae-save").click()
        page.wait_for_function("() => /Saved/.test(document.getElementById('ae-save-msg').textContent)", timeout=10000)
        upd = next(a for a in self.api(req, "/assets") if a["id"] == target["id"])
        self.check(upd["owner"] == owner and upd["criticality"] == crit and upd["site"] == "Plant A", f"[assets] PATCH not applied: {upd['owner']}, {upd['criticality']}, {upd['site']}")
        # owner 2026-10-13: the IEC 62443 zone is set from the asset panel (zone created when missing)
        page.locator("[data-testid=ae-zone]").fill("Smoke Asset Zone")
        page.locator("#ae-save").click()
        page.wait_for_function("() => /Saved: .*iec_zone/.test(document.getElementById('ae-save-msg').textContent)", timeout=10000)
        upd = next(a for a in self.api(req, "/assets") if a["id"] == target["id"])
        self.check(upd["iec_zone"] == "Smoke Asset Zone"
                   and any(z["name"] == "Smoke Asset Zone" for z in self.api(req, "/iec-zones")["zones"]),
                   f"[assets] zone not set / zone not created: {upd.get('iec_zones')}")
        page.locator("#assets-reload").click()
        page.wait_for_load_state("networkidle")
        page.locator("#a-zone").select_option("Smoke Asset Zone")
        self.check(page.locator("#assets-tbody tr").count() == 1
                   and "Smoke Asset Zone" in page.locator("#assets-tbody tr [data-testid=asset-zone]").first.inner_text(),
                   "[assets] zone filter / column")
        page.locator("#a-zone").select_option("")
        self.assets_stale(page, req)
        self.assets_inventory(page, req)
        self.assets_import(page, req)

    def assets_inventory(self, page, req):
        """SF-5 follow-up: Inventory column and listed / unlisted / unknown filter follow the API."""
        assets = self.api(req, "/assets")
        for value in ("listed", "unlisted", "unknown"):
            want = self.api(req, f"/assets?inventory={value}")
            page.locator("#a-inv").select_option(value)
            shown = page.locator("#assets-tbody tr").count()
            self.check(shown == len(want), f"[assets] inventory={value}: {shown} rows shown, API {len(want)}")
            sel = ('td[data-inventory="unlisted"], td[data-inventory="unknown"]' if value == "unlisted"
                   else f'td[data-inventory="{value}"]')          # unlisted includes the unclassified subset
            self.check(page.locator("#assets-tbody " + sel.replace(", ", ", #assets-tbody ")).count() == shown,
                       f"[assets] inventory={value}: column badge disagrees with the filter")
        page.locator("#a-inv").select_option("")
        self.check(page.locator("#assets-tbody tr").count() == len(assets), "[assets] inventory filter not cleared")
        unknown = self.api(req, "/assets?inventory=unknown")
        if unknown:
            page.locator(f'#assets-tbody tr[data-asset-id="{unknown[0]["id"]}"]').click()
            self.check("not in any inventory and unclassified" in page.locator("#assets-side").inner_text().lower(),
                       "[assets] panel does not say the host is not in any inventory")
        self.shot(page, "assets_inventory")

    def assets_import(self, page, req):
        """Import CSV with a column mapping: suggestions, checks, mapped import, saved mapping."""
        xss = '<img src=x data-xss=1 onerror="window.__xss=(window.__xss||0)+1">'
        body = ('Col A,Col B,Device,Asset Type,"' + xss.replace('"', '""') + '"\n'
                "10.77.0.5,aa:bb:cc:77:00:05,SMOKE-PLC,PLC,x\n"
                "10.77.0.6,,SMOKE-HMI,Operator Panel,y\n").encode()
        site = self.site_id(req, "plant-a")
        for m in req.get(self.base + f"/ingest/baseline/asset-inventory/mappings?site={site}").json()["mappings"]:
            req.delete(self.base + f"/ingest/baseline/asset-inventory/mappings/{m['id']}?site={site}")

        def preview_after(action):
            with page.expect_response(lambda r: r.url.split("?")[0].endswith("/asset-inventory/preview")) as ri:
                action()
            page.wait_for_function("() => !/Reading/.test(document.getElementById('imp-status').textContent)", timeout=10000)
            return ri.value.json()

        page.locator("#assets-import-btn").click()
        page.wait_for_selector("#imp-dialog[open]", timeout=5000)
        p = preview_after(lambda: page.locator("#imp-file").set_input_files(
            files=[{"name": "cmms.csv", "mimeType": "text/csv", "buffer": body}]))
        self.check(page.locator("#imp-columns tr").count() == 5, "[assets-import] column rows != 5")
        field = lambda key: page.locator(f'#imp-columns select[data-col="{key}"]')
        self.check(field("col a").input_value() == "ip" and field("col b").input_value() == "mac",
                   f"[assets-import] address columns not suggested from their values: {p['column_map']}")
        self.check(field("asset type").input_value() == "device_type", "[assets-import] 'Asset Type' not mapped")
        self.check("check" in page.locator('#imp-columns tr[data-col="col a"]').inner_text(),
                   "[assets-import] value-based suggestion not marked for checking")
        self.check("Operator Panel" in page.locator("[data-testid=inv-import-unknown-types]").inner_text(),
                   "[assets-import] unknown device type not listed")
        # ignore the name column; then remove both identity columns -> blocked
        p = preview_after(lambda: field("device").select_option(""))
        self.check(p["column_map"]["device"] == "" and "Device" in p["ignored_columns"], "[assets-import] ignore not sent")
        preview_after(lambda: field("col a").select_option(""))
        p = preview_after(lambda: field("col b").select_option(""))
        self.check(not p["can_import"] and page.locator("[data-testid=inv-import-errors]").count() == 1
                   and page.locator("#imp-run").is_disabled(), "[assets-import] missing identity not blocking")
        preview_after(lambda: field("col a").select_option("ip"))
        p = preview_after(lambda: field("col b").select_option("mac"))
        self.check(p["can_import"] and not page.locator("#imp-run").is_disabled(), "[assets-import] import not enabled")
        page.locator("#imp-save").check()
        page.locator("#imp-save-name").fill("smoke-map")
        with page.expect_response(lambda r: r.url.split("?")[0].endswith("/ingest/baseline/asset-inventory")
                                  and r.request.method == "POST") as ri:
            page.locator("#imp-run").click()
        r = ri.value.json()
        page.wait_for_function("() => /imported/.test(document.getElementById('imp-result').textContent)", timeout=10000)
        self.check(r["stats"]["hosts_created_or_updated"] == 2 and r["mapping_saved"]["name"] == "smoke-map",
                   f"[assets-import] import result {r.get('stats')}")
        self.check("device" in r["stats"]["columns_ignored"], "[assets-import] ignored column not reported")
        hosts = {a["ip"]: a for a in self.api(req, "/assets")}
        self.check(hosts.get("10.77.0.5", {}).get("device_type") == "plc"
                   and not hosts.get("10.77.0.5", {}).get("hostname"), "[assets-import] mapped values not applied")
        page.wait_for_function("() => [...document.querySelectorAll('#assets-tbody tr')].some(t => t.textContent.includes('10.77.0.5'))",
                               timeout=10000)
        self.check("smoke-map" in page.locator("#imp-mapping").inner_text(), "[assets-import] saved mapping not offered")
        # the next file from the same system maps itself
        page.locator("#imp-mapping").select_option("")
        p = preview_after(lambda: page.locator("#imp-file").set_input_files(
            files=[{"name": "cmms2.csv", "mimeType": "text/csv", "buffer": body}]))
        self.check(p["saved_mapping"] == "smoke-map" and field("device").input_value() == "",
                   "[assets-import] saved mapping not applied to the next file")
        self.check('saved mapping "smoke-map"' in page.locator("#imp-status").inner_text(), "[assets-import] status does not name the mapping")
        self.shot(page, "assets_import")
        # delete the saved mapping (two clicks)
        mid = r["mapping_saved"]["id"]
        page.locator("#imp-mapping").select_option(str(mid))
        page.wait_for_load_state("networkidle")
        page.locator("#imp-mapping-del").click()
        with page.expect_response(lambda r: f"/mappings/{mid}" in r.url and r.request.method == "DELETE"):
            page.locator("#imp-mapping-del").click()
        page.wait_for_load_state("networkidle")
        left = req.get(self.base + f"/ingest/baseline/asset-inventory/mappings?site={site}").json()["mappings"]
        self.check(left == [], f"[assets-import] mapping not deleted: {left}")
        page.locator("[data-testid=inv-import-close]").click()
        self.check(page.locator("#imp-dialog[open]").count() == 0, "[assets-import] dialog not closed")

    def assets_stale(self, page, req):
        """F-09: stale column/filter, address history panel, Mark stale hosts."""
        assets = self.api(req, "/assets")
        stale = [a for a in assets if a["stale"]]
        self.check(page.locator('#assets-tbody tr[data-stale="1"]').count() == len(stale), "[assets] stale rows != API")
        self.check(page.locator("#assets-tbody [data-testid=stale-badge]").count() == len(stale), "[assets] stale badges != API")
        page.locator("#a-stale").select_option("stale")
        self.check(page.locator("#assets-tbody tr").count() == len(stale), "[assets] stale filter wrong")
        if stale:
            page.locator(f'#assets-tbody tr[data-asset-id="{stale[0]["id"]}"]').click()
            self.check(page.locator("#assets-side .panel-badges [data-testid=stale-badge]").count() == 1, "[assets] stale badge missing in detail")
            hist = self.api(req, f"/hosts/{stale[0]['id']}/history")["history"]
            page.wait_for_selector("#assets-side .host-history .detail-label:has-text('Address history (')", timeout=10000)
            self.check(page.locator("#assets-side .host-history [data-history-id]").count() == min(len(hist), 40), "[assets] history rows != API")
        page.locator("#a-stale").select_option("")
        # last seen sort
        page.locator('#assets-thead th:has-text("Last seen")').click()
        # Mark stale hosts: 0 days flags every host seen before now
        page.locator("#a-stale-days").fill("-3")
        page.locator("#a-mark-stale").click()
        self.check("whole number" in page.locator("#a-stale-msg").inner_text(), "[assets] bad days not rejected client-side")
        page.locator("#a-stale-days").fill("0")
        with page.expect_response(lambda r: "/hosts/mark-stale" in r.url and r.request.method == "POST") as ri:
            page.locator("#a-mark-stale").click()
        resp = ri.value
        self.check("older_than_days=0" in resp.url, f"[assets] days not sent: {resp.url}")
        r = resp.json()
        page.wait_for_function("() => /flagged stale/.test(document.getElementById('a-stale-msg').textContent)", timeout=10000)
        msg = page.locator("#a-stale-msg").inner_text()
        self.check(msg.startswith(f"{r['marked_stale']} host") and f"{r['stale_total']} stale in total" in msg, f"[assets] mark-stale message {msg!r} vs {r}")
        page.wait_for_load_state("networkidle")
        now_stale = sum(1 for a in self.api(req, "/assets") if a["stale"])
        self.check(now_stale == r["stale_total"], "[assets] stale_total != API after mark")
        self.check(page.locator('#assets-tbody tr[data-stale="1"]').count() == now_stale, "[assets] table not refreshed after mark-stale")
        self.shot(page, "assets_stale")
        # restore: un-flag (a large window clears hosts seen since)
        req.post(self.base + f"/hosts/mark-stale?older_than_days=60&site_id={self.site_id(req, 'plant-a')}")

    def report_checks(self, page, req):
        """Owner 2026-10-14: Checks in the report - groups with tri-state checkboxes, saved per
        site with a reason; the PDF link can ignore the selection."""
        page.wait_for_selector("[data-testid=rc-group-check][data-group=fortigate]", timeout=15000)
        page.locator("[data-testid=rc-reason]").fill("smoke: covered by the CIS audit")
        with page.expect_response(lambda r: "/reports/check-selection" in r.url and r.request.method == "PUT"):
            page.locator("[data-testid=rc-group-check][data-group=fortigate]").click()
        sel = self.api(req, "/reports/check-selection")
        fg = next(g for g in sel["groups"] if g["key"] == "fortigate")
        self.check(fg["state"] == "none" and fg["checks"][0].get("reason") == "smoke: covered by the CIS audit",
                   f"[system] FortiGate (CIS) group not left out: {fg['state']}")
        self.check(page.locator("[data-testid=report-excluded-note]").is_visible(), "[system] excluded note not shown by the PDF link")
        page.locator("[data-testid=report-all-checks]").check()
        self.check("all_checks=true" in (page.locator("#rep-download").get_attribute("href") or ""), "[system] all_checks not in the PDF link")
        page.locator("[data-testid=report-all-checks]").uncheck()
        page.locator("[data-testid=report-layout]").select_option("public")          # owner 2026-10-18: the public compliance report
        self.check("layout=public" in (page.locator("#rep-download").get_attribute("href") or ""), "[system] layout not in the PDF link")
        page.locator("[data-testid=report-layout]").select_option("")
        with page.expect_response(lambda r: "/reports/check-selection" in r.url and r.request.method == "PUT"):
            page.locator("[data-testid=rc-include-all]").click()
        self.check(self.api(req, "/reports/check-selection")["excluded"] == 0, "[system] Include every check did not restore")

    def report_details(self, page, req):
        """Owner 2026-10-18: report details (cover, distribution list, revision history) saved per site."""
        page.wait_for_selector("[data-testid=rd-client]", timeout=15000)
        page.locator("[data-testid=rd-client]").fill("Smoke Client <img src=x onerror=window.__xss=1>")
        page.locator("[data-testid=rd-project]").fill("Smoke project")
        page.locator("[data-testid=rd-version]").fill("0.9")
        page.locator("[data-testid=rd-poc-add]").click()
        row = page.locator("[data-testid=rd-poc-row]").last
        row.locator("[data-field=name]").fill("Sam Smoke")
        row.locator("[data-field=role]").fill("OT Security")
        page.locator("[data-testid=rd-poc-add]").click()
        page.locator("[data-testid=rd-poc-row]").last.locator("[data-field=name]").fill("Second POC")
        page.locator("[data-testid=rd-dist-add]").click()
        page.locator("[data-testid=rd-dist-row]").last.locator("[data-field=name]").fill("Assessor Smoke")
        page.locator("[data-testid=rd-revs-add]").click()
        rrow = page.locator("[data-testid=rd-revs-row]").last
        rrow.locator("[data-field=version]").fill("0.9")
        rrow.locator("[data-field=status]").fill("Smoke draft")
        with page.expect_response(lambda r: "/reports/details" in r.url and r.request.method == "PUT"):
            page.locator("[data-testid=rd-save]").click()
        page.wait_for_function("() => /Saved/.test(document.querySelector('[data-testid=rd-msg]')?.textContent || '')", timeout=10000)
        d = self.api(req, "/reports/details")
        self.check(d["client_name"].startswith("Smoke Client") and d["version"] == "0.9", "[system] report details not stored")
        self.check(any(x["name"] == "Sam Smoke" for x in d["distribution"]) and any(x["status"] == "Smoke draft" for x in d["revisions"]),
                   "[system] distribution / revision rows not stored")
        self.check([x["side"] for x in d["distribution"] if x["name"] in ("Sam Smoke", "Second POC")] == ["client", "client"]
                   and any(x["name"] == "Assessor Smoke" and x["side"] == "assessor" for x in d["distribution"]),
                   "[system] client POCs / assessor sides not stored")
        self.check(page.evaluate("() => window.__xss") is None, "[system] XSS payload executed in the report details form")

    def audit_checklist(self, page, req):
        """Owner 2026-10-24: the Master Audit Checklist workbook -> preview / PDF / CSV on the Reports page."""
        import io as _io
        import openpyxl
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Master Checklist"
        ws.append(["#", "Master ID", "Domain", "Check title", "Audit check (paraphrased)", "Suggested evidence", "Covers (source Req IDs)",
                   "Source standards", "NIST firewall reference", "FR", "Min SL", "Audit scope", "Conditional", "Status", "Maturity Level",
                   "Finding / Observation", "Evidence Reviewed", "Severity", "Recommendation", "Owner", "Target Date"])
        ws.append([1, "GOV-01", "Governance, program & policy", "Security program <img src=x onerror=window.__xss=1>", "Is there a program?", "SP document",
                   "ORG 1.1", "2-1", None, "Program", 1, None, "No", "Non-compliant", 1, "No program <script>window.__xss=1</script>", "Interview",
                   "High", "Write one.", "CISO", "2027-01-31"])
        ws.append([2, "GOV-02", "Governance, program & policy", "Program scope", "Is the scope defined?", "Scope statement", "1-1 §1", "1-1", None,
                   "Program", 1, None, "No", "Compliant", 3, None, None, None, None, None, None])
        buf = _io.BytesIO()
        wb.save(buf)
        page.locator("[data-testid=ac-file]").set_input_files({"name": "smoke_checklist.xlsx", "buffer": buf.getvalue(),
                                                               "mimeType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
        with page.expect_response(lambda r: "/reports/audit-checklist" in r.url and "format=json" in r.url):
            page.locator("[data-testid=ac-check]").click()
        page.wait_for_selector("[data-testid=ac-summary]", timeout=15000)
        summary = page.locator("[data-testid=ac-summary]").inner_text()
        self.check("2 check(s)" in summary and "1 finding(s)" in summary, f"[system] audit checklist preview wrong: {summary!r}")
        self.check(page.locator("[data-testid=ac-item]").count() == 1, "[system] audit checklist preview should list one finding")
        self.check("Security program <img" in page.locator("[data-testid=ac-item]").first.inner_text(), "[system] audit checklist title not shown as text")
        page.locator("[data-testid=ac-scope]").select_option("all")
        with page.expect_download(timeout=30000) as dl:
            page.locator("[data-testid=ac-csv]").click()
        body = open(dl.value.path(), "rb").read().decode("utf-8")
        self.check(body.startswith("\ufeffSection,Master ID") and body.count("\r\n") == 3, "[system] audit checklist CSV wrong")
        page.locator("[data-testid=ac-client]").fill("Smoke Audit Client")
        page.locator("[data-testid=ac-author]").fill("Smoke Author")
        page.locator("[data-testid=ac-date]").fill("2026-10-24")
        page.locator("[data-testid=ac-poc-add]").click()
        page.locator("[data-testid=ac-poc-row]").last.locator("[data-field=name]").fill("Smoke POC One")
        page.locator("[data-testid=ac-poc-add]").click()
        page.locator("[data-testid=ac-poc-row]").last.locator("[data-field=name]").fill("Smoke POC Two")
        page.locator("[data-testid=ac-lrqa-add]").click()
        page.locator("[data-testid=ac-dist-row]").last.locator("[data-field=name]").fill("Smoke Consultant")
        with page.expect_download(timeout=60000) as dl:
            page.locator("[data-testid=ac-pdf]").click()
        pdf = open(dl.value.path(), "rb").read()
        self.check(pdf[:5] == b"%PDF-" and dl.value.suggested_filename.endswith(".pdf"), "[system] audit checklist PDF not downloaded")
        try:
            import pypdf
            text = "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(_io.BytesIO(pdf)).pages)
            self.check(all(x in text for x in ("Smoke Audit Client", "Smoke Author", "2026-10-24", "Smoke POC One", "Smoke POC Two", "Smoke Consultant", "LRQA consultants")),
                       "[system] audit checklist PDF lacks the cover / distribution details typed on the card")
        except ImportError:
            pass
        page.wait_for_selector("[data-testid=ac-done]", timeout=10000)
        self.check(page.evaluate("() => window.__xss") is None, "[system] XSS payload executed in the audit checklist preview")

    def s_system(self, page, req):
        """F-02 report link, F-17 diagnostics, review run on the System page."""
        self.report_checks(page, req)
        self.report_details(page, req)
        self.audit_checklist(page, req)
        a = page.locator("#rep-download")
        href = a.get_attribute("href")
        u = urllib.parse.urlparse(href)
        self.check(u.path == "/reports/compliance.pdf" and u.query == f"site_id={self.cur_site}",
                   f"[system] default report href {href}")
        self.check(a.get_attribute("download") is not None, "[system] report link not a download link")
        page.locator("#rep-baseline").select_option("B1")
        page.locator("#rep-closed").check()
        page.locator("#rep-site").fill('Plant <b>A</b> & "B"')
        page.locator("#rep-sl").select_option("2")
        href = a.get_attribute("href")
        q = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
        self.check(q == {"baseline": ["B1"], "include_closed": ["true"], "site": ['Plant <b>A</b> & "B"'],
                         "target_sl": ["2"], "site_id": [str(self.cur_site)]}, f"[system] report query {q}")
        page.locator("#rep-zones").uncheck()
        q = urllib.parse.parse_qs(urllib.parse.urlparse(a.get_attribute("href")).query)
        self.check(q.get("include_zones") == ["false"], f"[system] zones option not in the query: {q}")
        page.locator("#rep-zones").check()
        self.check("include_zones" not in a.get_attribute("href"), "[system] zones option default not on")
        with page.expect_download(timeout=120000) as dl:
            a.click()
        d = dl.value
        self.check(d.suggested_filename.startswith("iasc_compliance_") and d.suggested_filename.endswith(".pdf"), f"[system] download name {d.suggested_filename}")
        path = d.path()
        self.check(path and Path(path).read_bytes()[:5] == b"%PDF-", "[system] downloaded file is not a PDF")
        # diagnostics: the findings section already ran reviews in this server process
        diag = self.api(req, "/diagnostics")
        body = page.locator("#diag-body").inner_text()
        if diag["last_review"]["finished_at"]:
            self.check("Finished" in body and "Escalations" in body, "[system] last review not shown")
        else:
            self.check("No review has run" in body, "[system] empty last_review not explained")
        self.check(f"unknown check names ({len(diag['unknown_check_names'])})" in body.lower(), "[system] unknown check names count")
        with page.expect_response(lambda r: "/reviews/run" in r.url, timeout=120000) as ri:
            page.locator("#system-run-reviews").click()
        r = ri.value.json()
        page.wait_for_selector("#system-run-result [data-testid=review-run]", timeout=30000)
        got = page.locator('#system-run-result [data-stat="total_findings"] b').inner_text()
        self.check(got == str(r["total_findings"]), f"[system] review total {got} != {r['total_findings']}")
        page.wait_for_function("() => /Finished/.test(document.getElementById('diag-body').textContent)", timeout=15000)
        page.wait_for_load_state("networkidle")

    # ---------------------------------------------------------------- sites
    def s_sites(self, page, req):
        """Global site selector + required site picker (multi-site phase 1)."""
        sites = self.api(req, "/sites")
        names = {x["name"] for x in sites}
        # FI-01: no implicit Default site - only the two seeded sites
        self.check({"Plant A", "Plant B"} <= names and "Default" not in names,
                   f"[sites] expected Plant A + Plant B and no Default, got: {names}")
        opts = page.locator("#site-select option").evaluate_all("os => os.map(o => [o.value, o.textContent])")
        # always one site (owner 2026-10-13): no "All sites" option
        self.check(all(v for v, _ in opts) and not any("All sites" in t for _, t in opts), f"[sites] selector offers 'All sites': {opts}")
        self.check(sorted(v for v, _ in opts) == sorted(str(x["id"]) for x in sites), "[sites] selector options != /sites")
        a_id, b_id = self.site_id(req, "plant-a"), self.site_id(req, "plant-b")

        # --- required site on uploads
        self.goto(page, "ingest")
        page.locator("#ing-kind").select_option("syslog")
        # phase 3: log uploads show the picker as the OPTIONAL "map unknown devices" site
        self.check(page.locator("#ing-site-group").is_visible()
                   and "Map unknown devices" in page.locator("#ing-site-label").inner_text(),
                   "[sites] log upload: optional map-to-site picker not shown")
        page.locator("#ing-kind").select_option("arp")
        self.check(page.locator("#ing-site-group").is_visible(), "[sites] site picker hidden for an ARP upload")
        page.locator("#ing-site").select_option("")
        page.locator("#ing-file").set_input_files(str(ROOT / "sample_data" / "sample_arp_unix.txt"))
        n_before = len(self.events)
        page.locator("#ing-submit-btn").click()
        page.wait_for_selector("#ing-result.err", timeout=5000)
        self.check("Choose the site" in page.locator("#ing-result").inner_text(), "[sites] missing-site message not shown")
        self.check(len(self.events) == n_before, "[sites] a request was sent without a site")
        self.check("invalid" in (page.locator("#ing-site").get_attribute("class") or ""), "[sites] picker not flagged invalid")
        # unknown site -> the server's 422 detail is shown
        self.allowed.append("/ingest/arp")
        page.evaluate("() => { const s = document.getElementById('ing-site'); s.append(new Option('ghost', '999999')); s.value = '999999'; }")
        page.locator("#ing-submit-btn").click()
        page.wait_for_function("() => /HTTP 422/.test(document.getElementById('ing-result').textContent)", timeout=10000)
        self.check("Unknown site" in page.locator("#ing-result").inner_text(), "[sites] 422 unknown-site detail not shown")
        # inline "+ New site", then upload into it
        page.locator("[data-testid=ing-site-new]").click()
        page.locator("[data-testid=ing-site-new-name]").fill("Smoke Site")
        page.locator("[data-testid=ing-site-create]").click()
        page.wait_for_function("() => /created/.test(document.querySelector('#ing-site-pick .site-pick-msg').textContent)", timeout=10000)
        smoke = next((x for x in self.api(req, "/sites") if x["name"] == "Smoke Site"), None)
        if self.check(smoke is not None, "[sites] inline-created site not stored"):
            self.check(page.locator("#ing-site").input_value() == str(smoke["id"]), "[sites] new site not selected in the picker")
            self.check(page.locator(f'#site-select option[value="{smoke["id"]}"]').count() == 1, "[sites] new site missing from the global selector")
            page.locator("#ing-vendor").select_option("unix")
            page.locator("#ing-file").set_input_files(str(ROOT / "sample_data" / "sample_arp_unix.txt"))
            page.locator("#ing-submit-btn").click()
            page.wait_for_selector("#ing-result.ok", timeout=15000)
            self.check('"site": "Smoke Site"' in page.locator("#ing-result").inner_text(), "[sites] upload response not for Smoke Site")

        # --- global selector filters every list
        page.locator("#site-select").select_option(str(b_id))
        self.check(page.locator("#ing-site").input_value() == str(b_id), "[sites] upload picker does not follow the global site")
        self.goto(page, "topology")
        t = self.api(req, f"/topology?site_id={b_id}")
        shown = page.locator(".host-node").evaluate_all("ns => ns.flatMap(n => (n.dataset.nodeIds || n.dataset.nodeId).split(' '))")
        self.check(len(shown) == len(t["nodes"]), f"[sites] Plant B topology nodes != API ({len(t['nodes'])})")
        self.check(page.locator(".fw-boundary-chip").count() == len(t["firewall_boundaries"]), "[sites] Plant B boundary chips != API")
        self.goto(page, "fw")
        devs = self.api(req, f"/firewall-devices?site_id={b_id}")
        self.check(page.locator(".fw-device-card").count() == len(devs) and len(devs) >= 2, f"[sites] Plant B firewall cards != API ({len(devs)})")
        names_shown = page.locator(".fw-device-card").all_inner_texts()
        # FW-OT exists in BOTH plants (same config - phase 2 isolation); FW-LEGACY only in Plant A
        self.check(not any("FW-LEGACY" in t_ for t_ in names_shown), "[sites] Plant A firewall shown under Plant B")
        self.goto(page, "findings")
        summ = self.api(req, f"/findings/summary?site_id={b_id}")
        page_text = page.locator("#findings-summary").inner_text()
        self.check(str(summ["total_open"]) in page_text, f"[sites] findings summary not scoped to Plant B ({summ['total_open']}): {page_text[:120]!r}")
        # persisted across a reload
        page.reload()
        page.wait_for_load_state("networkidle")
        self.check(page.locator("#site-select").input_value() == str(b_id), "[sites] site choice not remembered after reload")
        # back to Plant A: only its firewalls
        page.locator("#site-select").select_option(str(a_id))
        self.cur_site = a_id
        page.wait_for_load_state("networkidle")
        self.goto(page, "fw")
        self.check(page.locator(".fw-device-card").count() == len(self.api(req, f"/firewall-devices?site_id={a_id}")),
                   "[sites] Plant A firewall cards != API")
        self.sites_phase2(page, req, a_id, b_id)

    def sites_phase2(self, page, req, a_id, b_id):
        """Isolation of overlapping data + per-site pages under 'All sites'."""
        fa = [f for f in self.api(req, f"/topology/firewalls?site_id={a_id}")["firewalls"] if f["name"] == "FW-OT"]
        fb = [f for f in self.api(req, f"/topology/firewalls?site_id={b_id}")["firewalls"] if f["name"] == "FW-OT"]
        self.check(len(fa) == 1 and len(fb) == 1 and fa[0]["id"] != fb[0]["id"],
                   f"[sites] FW-OT not one independent firewall per site: {fa} / {fb}")
        ips = lambda sid: {h["ip"] for h in self.api(req, f"/hosts?site_id={sid}&limit=5000") if h.get("ip")}
        self.check(bool(ips(a_id) & ips(b_id)), "[sites] seed has no overlapping IPs between Plant A and Plant B")
        fids = lambda sid: {f["id"] for f in self.api(req, f"/findings?site_id={sid}&limit=5000")}
        self.check(not (fids(a_id) & fids(b_id)), "[sites] a finding is listed under two sites")
        # cross-site reference -> 422
        r = req.post(self.base + "/topology/set-upstream", data={"firewall_id": fa[0]["id"], "upstream_firewall_id": fb[0]["id"]})
        self.check(r.status == 422, f"[sites] cross-site set-upstream not rejected ({r.status})")
        # always one site: per-site pages never ask for a site, and the report
        # link is scoped to the selected site (the explicit roll-up still works)
        for sec in ("topology", "fwtopo", "reach", "accessreview", "shadow"):
            self.goto(page, sec)
            self.check(page.locator(f"[data-testid=site-required-{sec}]").count() == 0
                       or page.locator(f"[data-testid=site-required-{sec}]").is_hidden(),
                       f"[sites] {sec}: 'select a site' prompt shown with a site selected")
        self.goto(page, "system")
        q = urllib.parse.parse_qs(urllib.parse.urlparse(page.locator("#rep-download").get_attribute("href") or "").query)
        self.check(q.get("site_id") == [str(a_id)], f"[sites] report link not scoped to the site: {q}")
        page.locator("#rep-all").check()
        q = urllib.parse.parse_qs(urllib.parse.urlparse(page.locator("#rep-download").get_attribute("href") or "").query)
        self.check(q.get("all_sites") == ["true"] and "site_id" not in q, f"[sites] roll-up link query {q}")
        page.locator("#rep-all").uncheck()
        # a remembered site that no longer exists: the default / first site is chosen
        page.evaluate("() => { try { localStorage.setItem('iasc_site', '999999'); } catch (e) {} }")
        page.reload()
        page.wait_for_load_state("networkidle")
        chosen = page.locator("#site-select").input_value()
        self.check(chosen in {str(x["id"]) for x in self.api(req, "/sites")}, f"[sites] no site chosen after an unknown one: {chosen!r}")
        page.locator("#site-select").select_option(str(a_id))
        self.cur_site = a_id
        page.wait_for_load_state("networkidle")

    def s_b23(self, page, req):
        """B-23: stale responses of the previous site are dropped (site switch
        while a request is in flight), keyboard access to finding rows, asset
        rows and sortable headers."""
        a_id, b_id = self.site_id(req, "plant-a"), self.site_id(req, "plant-b")

        def hold_while_switching(section, url_re, ready_js):
            """Hold every Plant A request matching url_re, reload the section,
            switch to Plant B while they are in flight, then release them."""
            page.locator("#site-select").select_option(str(a_id))
            self.cur_site = a_id
            self.goto(page, section)
            held = []
            pat = re.compile(url_re % a_id)
            matcher = lambda u: bool(pat.search(u))
            page.route(matcher, lambda route: held.append(route))
            page.locator(f"#{section}-reload" if section != "topology" else "#topo-reload").click()
            for _ in range(100):
                if held:
                    break
                page.wait_for_timeout(50)
            self.check(bool(held), f"[b23] {section}: no Plant A request to hold")
            page.locator("#site-select").select_option(str(b_id))
            self.cur_site = b_id
            page.wait_for_function(ready_js, timeout=20000)
            page.wait_for_load_state("networkidle")
            for r in held:                 # the late (old-site) answers arrive now
                try:
                    r.continue_()
                except Exception:          # noqa: BLE001 - aborted by the page already
                    pass
            page.unroute(matcher)
            page.wait_for_timeout(1200)
            return len(held)

        # findings: summary + list must be Plant B's after the late Plant A answers
        n = hold_while_switching(
            "findings", r"/findings(/summary)?\?(.*&)?site_id=%d(&|$)",
            "() => !/Loading/.test(document.getElementById('findings-status').textContent)")
        summ = self.api(req, f"/findings/summary?site_id={b_id}")
        txt = page.locator('#findings-summary .st-card[data-status="open"] .summary-count').inner_text()
        self.check(int(txt) == summ["by_status"].get("open", 0),
                   f"[b23] findings: open card {txt} is not Plant B's {summ['by_status'].get('open', 0)} after {n} late Plant A response(s)")
        size = int(page.locator("#f-limit").input_value())
        want = [str(f["id"]) for f in self.api(req, f"/findings?limit={size}&offset=0&site_id={b_id}")]
        got = page.locator(".finding-row").evaluate_all("rs => rs.map(r => r.dataset.findingId)")
        self.check(got == want, "[b23] findings: list rows are not Plant B's first page after the site switch")
        # topology (uses apiAll for /hosts): nodes must be Plant B's
        hold_while_switching(
            "topology", r"/(topology|hosts)\?(.*&)?site_id=%d(&|$)",
            "() => !/Loading/.test(document.getElementById('topology-status').textContent)")
        t = self.api(req, f"/topology?site_id={b_id}")
        ids = sorted(page.locator(".host-node").evaluate_all("ns => ns.flatMap(n => (n.dataset.nodeIds || n.dataset.nodeId).split(' '))"))
        self.check(ids == sorted(str(x["id"]) for x in t["nodes"]), "[b23] topology: nodes are not Plant B's after the site switch")
        self.shot(page, "b23_race_topology")

        # keyboard: Tab to a finding row, Enter opens the side panel
        self.goto(page, "findings")
        page.locator("#f-search").focus()
        reached = None
        for _ in range(60):
            page.keyboard.press("Tab")
            reached = page.evaluate("() => document.activeElement && document.activeElement.classList.contains('finding-row') ? document.activeElement.dataset.findingId : null")
            if reached:
                break
        if self.check(reached is not None, "[b23] Tab never reached a finding row"):
            self.check(page.evaluate("() => getComputedStyle(document.activeElement).outlineStyle") != "none",
                       "[b23] focused finding row has no visible focus outline")
            page.keyboard.press("Enter")
            page.wait_for_selector("#f-edit-status", timeout=5000)
            self.check(page.locator(f'.finding-row.selected[data-finding-id="{reached}"]').count() == 1,
                       "[b23] Enter did not select the focused finding row")
            self.check(page.evaluate("() => document.activeElement.dataset.findingId") == reached,
                       "[b23] focus lost after selecting a finding with Enter")
            self.check(page.locator(f'.finding-row[data-finding-id="{reached}"]').get_attribute("aria-pressed") == "true",
                       "[b23] selected finding row not aria-pressed")
            # Space on the next row
            page.keyboard.press("Tab")
            nxt = page.evaluate("() => document.activeElement.classList.contains('finding-row') ? document.activeElement.dataset.findingId : null")
            if nxt:
                page.keyboard.press(" ")
                page.wait_for_selector(f'.finding-row.selected[data-finding-id="{nxt}"]', timeout=5000)

        # keyboard: sortable inventory header toggles aria-sort; Enter on a row opens it
        self.goto(page, "assets")
        th = page.locator('#assets-thead th[data-col="hostname"]')
        self.check(th.get_attribute("aria-sort") == "none", "[b23] unsorted header lacks aria-sort=none")
        page.locator('#assets-thead .th-btn[data-sort="hostname"]').focus()
        page.keyboard.press("Enter")
        self.check(th.get_attribute("aria-sort") == "ascending", f"[b23] Enter on header: aria-sort={th.get_attribute('aria-sort')}")
        self.check(page.evaluate("() => document.activeElement.dataset.sort") == "hostname", "[b23] focus left the sort header")
        page.keyboard.press(" ")
        self.check(th.get_attribute("aria-sort") == "descending", f"[b23] Space on header: aria-sort={th.get_attribute('aria-sort')}")
        self.check(page.locator('#assets-thead th[data-col="ip"]').get_attribute("aria-sort") == "none", "[b23] other header not aria-sort=none")
        row = page.locator("#assets-tbody tr").first
        aid = row.get_attribute("data-asset-id")
        row.focus()
        page.keyboard.press("Enter")
        page.wait_for_selector("#ae-save", timeout=5000)
        self.check(page.locator(f'#assets-tbody tr[data-asset-id="{aid}"]').get_attribute("aria-selected") == "true",
                   "[b23] Enter on an inventory row did not select it")
        # keyboard: topology host node (role=button, Enter selects)
        self.goto(page, "topology")
        node = page.locator(".host-node").first
        nid = node.get_attribute("data-node-id")
        node.focus()
        page.keyboard.press("Enter")
        self.check(page.locator(f'.host-node.selected[data-node-id="{nid}"]').count() == 1,
                   "[b23] Enter on a topology host node did not select it")
        # every remaining clickable non-button element is focusable
        for sec, sel in (("fwtopo", ".iface-card"),):
            self.goto(page, sec)
            if page.locator(sel).count():
                c = page.locator(sel).first
                self.check(c.get_attribute("tabindex") == "0" and c.get_attribute("role") == "button", f"[b23] {sel} not keyboard operable")
                c.focus()
                page.keyboard.press("Enter")
                self.check(c.get_attribute("aria-pressed") == "true", f"[b23] Enter on {sel} did not select it")
        page.locator("#site-select").select_option(str(a_id))
        self.cur_site = a_id
        page.wait_for_load_state("networkidle")

    # ---------------------------------------------------------------- run
    def run(self):
        with sync_playwright() as p:
            browser = p.chromium.launch()
            req = SiteReq(p.request.new_context(), self)
            self.seed_disabled_rules(req)
            ctx = browser.new_context(viewport={"width": 1440, "height": 900})
            page = ctx.new_page()
            self.hook(page)
            page.goto(self.base + "/ui")
            page.evaluate("() => { try { localStorage.clear(); } catch (e) {} }")
            # Phase 2: analysis pages work on one site - run the sections in Plant A.
            self.cur_site = self.site_id(req, "plant-a")
            page.evaluate("(id) => { try { localStorage.setItem('iasc_site', String(id)); } catch (e) {} }", self.cur_site)
            page.goto(self.base + "/ui#ingest")
            page.reload()   # a hash-only goto does not reload: pick up the stored site
            page.wait_for_load_state("networkidle")
            self.check(page.locator("#site-select").input_value() == str(self.cur_site), "[setup] Plant A not preselected")
            for s in SECTIONS:
                print(f"- {s}")
                n_fail = len(self.failures)
                try:
                    self.goto(page, s)
                    getattr(self, "s_" + s)(page, req)
                except Exception as e:  # noqa: BLE001
                    import traceback
                    tb = traceback.extract_tb(e.__traceback__)
                    where = next((f"{f.name}:{f.lineno}" for f in reversed(tb) if f.filename.endswith("ui_smoke_index.py")), "?")
                    self.check(False, f"[{s}] exception at {where}: {type(e).__name__}: {e}")
                self.xss_clean(page, s)
                self.drain(s)
                page.wait_for_timeout(250)
                self.shot(page, s)
                if len(self.failures) == n_fail:
                    self.passed.append(s)

            print("- sites")
            n_fail = len(self.failures)
            try:
                self.s_sites(page, req)
            except Exception as e:  # noqa: BLE001
                self.check(False, f"[sites] exception: {type(e).__name__}: {e}")
            self.xss_clean(page, "sites")
            self.drain("sites")
            self.shot(page, "sites")
            if len(self.failures) == n_fail:
                self.passed.append("sites")

            print("- b23 (site race + keyboard)")
            n_fail = len(self.failures)
            try:
                self.s_b23(page, req)
            except Exception as e:  # noqa: BLE001
                self.check(False, f"[b23] exception: {type(e).__name__}: {e}")
            self.xss_clean(page, "b23")
            self.drain("b23")
            self.shot(page, "b23")
            if len(self.failures) == n_fail:
                self.passed.append("b23")

            # opened from file:// -> clear banner, no API calls attempted
            local = ROOT / "ui" / "index.html"
            if local.exists():
                print("- file:// banner")
                fctx = browser.new_context()
                fpage = fctx.new_page()
                fpage.goto(local.as_uri())
                self.check(fpage.locator("#file-banner").is_visible(), "[file] no banner when opened from file://")
                self.check("/ui" in fpage.locator("#file-banner").inner_text(), "[file] banner does not point to /ui")
                self.shot(fpage, "file_banner")
                fctx.close()

            # phone width: no horizontal page scroll anywhere
            print("- narrow (390px)")
            nctx = browser.new_context(viewport={"width": 390, "height": 844})
            npage = nctx.new_page()
            self.hook(npage)
            npage.goto(self.base + "/ui#ingest")
            npage.wait_for_load_state("networkidle")
            for s in SECTIONS:
                self.goto(npage, s)
                over = npage.evaluate("() => document.documentElement.scrollWidth - window.innerWidth")
                self.check(over <= 1, f"[narrow:{s}] page overflows horizontally by {over}px")
                self.xss_clean(npage, "narrow:" + s)
                self.shot(npage, s + "_narrow")
            # the expanded Access Review row (hop table) at phone width
            self.goto(npage, "accessreview")
            if self.cur_site is not None and npage.locator("#site-select").input_value() != str(self.cur_site):
                with npage.expect_response(lambda r: "/access-paths?" in r.url, timeout=15000):
                    npage.locator("#site-select").select_option(str(self.cur_site))
                npage.wait_for_load_state("networkidle")
            if not npage.locator("#ar-paths-table tr.ar-row").count() and npage.locator("#ar-paths-table tr.ar-group .ar-exp").count():
                npage.locator("#ar-paths-table tr.ar-group .ar-exp").first.click()      # every row rolled up: open a group
                npage.wait_for_timeout(150)
            exps = npage.locator("#ar-paths-table tr.ar-row .ar-exp")
            if self.check(exps.count() >= 1, "[narrow:accessreview] no path row to expand"):
                exps.first.click()
                npage.wait_for_timeout(150)
                over = npage.evaluate("() => document.documentElement.scrollWidth - window.innerWidth")
                self.check(over <= 1, f"[narrow:accessreview] expanded row overflows the page by {over}px")
                self.ar_hops_nowrap(npage, "#ar-main tr.ar-detail", "[narrow:accessreview]")
                self.shot(npage, "accessreview_detail_narrow")
            self.drain("narrow")
            browser.close()

        print(f"\nsections passed: {len(self.passed)}/{len(SECTIONS) + 2} {self.passed}")
        if self.failures:
            print(f"{len(self.failures)} failure(s):")
            for f in self.failures:
                print("  -", f)
            return 1
        print("all checks passed; screenshots in", self.shots)
        return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", help="server base URL, e.g. http://127.0.0.1:8765")
    ap.add_argument("--shots", default=os.path.join(tempfile.gettempdir(), "iasc_ui_smoke_index"), help="screenshot directory")
    a = ap.parse_args()
    sys.exit(Smoke(a.url, a.shots).run())


if __name__ == "__main__":
    main()
