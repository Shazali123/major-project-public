"""
Module 2: GoPhish Phishing Simulation (Phase 2 — Direct Simulation)

Architecture:
    1. Connect to GoPhish server (Ubuntu VM)
    2. Create a campaign with a phishing landing page
    3. This TEST MACHINE (Windows) directly simulates victim behaviour:
         - HTTP GET  the phishing URL  → triggers Windows Defender SmartScreen
         - HTTP POST fake credentials  → tests data-exfiltration detection
    4. If AV/SmartScreen BLOCKS the request  → DETECTED
       If phishing page loads fine           → NOT DETECTED
    5. Read GoPhish tracking results and clean up

Config: modules/module_2_gophish/gophish_config.json
"""

import os
import sys
import json
import time
import ssl
import tempfile
import urllib.request
import urllib.error
import urllib.parse
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_module import BaseModule
from system_monitor import SystemMonitor


# ---------------------------------------------------------------------------
# GoPhish REST API client (stdlib only — no pip dependencies)
# ---------------------------------------------------------------------------

class GoPhishClient:
    """Minimal GoPhish REST API client."""

    def __init__(self, host: str, api_key: str, timeout: int = 15):
        self.host    = host.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self._ctx    = self._no_verify_ssl()

    @staticmethod
    def _no_verify_ssl():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    def _request(self, method, path, data=None):
        url  = f"{self.host}/api{path}?api_key={self.api_key}"
        body = json.dumps(data).encode('utf-8') if data else None
        req  = urllib.request.Request(url, data=body, method=method)
        req.add_header('Content-Type', 'application/json')
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self._ctx) as resp:
                raw = resp.read().decode('utf-8')
                return resp.status, (json.loads(raw) if raw.strip() else {})
        except urllib.error.HTTPError as e:
            err = e.read().decode('utf-8', errors='replace')
            print(f"  [GoPhish API] HTTP {e.code} on {method} {path}: {err[:400]}")
            return e.code, {}

    def _get_list(self, path):
        """GET endpoint; handles plain-list and wrapped {data:[...]} responses."""
        code, data = self._request('GET', path)
        if code != 200:
            return []
        if isinstance(data, list):
            return data
        for key in ('data', 'results', 'items'):
            if isinstance(data.get(key), list):
                return data[key]
        return []

    # ---- Public API helpers ----

    def ping(self):
        try:
            code, _ = self._request('GET', '/campaigns/')
            return code == 200
        except Exception:
            return False

    def get_smtp_profiles(self): return self._get_list('/smtp/')
    def get_templates(self):      return self._get_list('/templates/')
    def get_pages(self):          return self._get_list('/pages/')

    def create_group(self, name, targets):
        code, data = self._request('POST', '/groups/', data={'name': name, 'targets': targets})
        return data if code in (200, 201) and isinstance(data, dict) else {}

    def delete_group(self, gid):
        try: self._request('DELETE', f'/groups/{gid}')
        except Exception: pass

    def create_campaign(self, payload):
        code, data = self._request('POST', '/campaigns/', data=payload)
        if code not in (200, 201):
            return {}
        return data if isinstance(data, dict) else {}

    def get_campaign_results(self, cid):
        code, data = self._request('GET', f'/campaigns/{cid}/results')
        return data if code == 200 and isinstance(data, dict) else {}

    def complete_campaign(self, cid):
        try: self._request('GET', f'/campaigns/{cid}/complete')
        except Exception: pass

    def delete_campaign(self, cid):
        try: self._request('DELETE', f'/campaigns/{cid}')
        except Exception: pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _by_name(items, name):
    """Case-insensitive name lookup."""
    nl = name.lower().strip()
    return next((i for i in items
                 if isinstance(i, dict) and i.get('name', '').lower().strip() == nl), None)


def _count_results(results_data):
    """Parse GoPhish result statuses into counters."""
    sent = opened = clicked = submitted = reported = 0
    for r in results_data.get('results', []):
        s = r.get('status', '')
        if s in ('Email Sent', 'Email Opened', 'Clicked Link',
                 'Submitted Data', 'Email Reported'):
            sent += 1
        if s in ('Email Opened', 'Clicked Link', 'Submitted Data', 'Email Reported'):
            opened += 1
        if s in ('Clicked Link', 'Submitted Data'):
            clicked += 1
        if s == 'Submitted Data':
            submitted += 1
        if s == 'Email Reported':
            reported += 1
    return sent, opened, clicked, submitted, reported


def _get_rids(results_data):
    """Extract GoPhish recipient tracking IDs from campaign results."""
    rids = []
    for r in results_data.get('results', []):
        rid = r.get('rid') or r.get('id')
        if rid:
            rids.append(str(rid))
    return rids


# ---------------------------------------------------------------------------
# HTTP simulation helpers (run on THIS Windows test machine)
# ---------------------------------------------------------------------------

def _make_plain_ssl():
    """SSL context for phishing page (self-signed or plain HTTP)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx


# Quarantine-poll settings (shared by all levels)
_POLL_INTERVAL = 0.1   # seconds between file-existence checks
_POLL_WINDOW   = 2.0   # seconds to wait per escalation level


def _av_poll(filepath):
    """Poll for up to _POLL_WINDOW seconds. Returns (quarantined, elapsed_s)."""
    deadline = time.monotonic() + _POLL_WINDOW
    while time.monotonic() < deadline:
        if not os.path.exists(filepath):
            elapsed = round(_POLL_WINDOW - (deadline - time.monotonic()), 2)
            return True, elapsed
        time.sleep(_POLL_INTERVAL)
    return False, _POLL_WINDOW


def _simulate_click(phish_url, rid, timeout=10):
    """
    Multi-level escalating AV detection test.
    L0: .html drop + quarantine poll.
    L1: Re-write payload as .ps1 (heuristic trigger).
    L2: Execute .ps1 via PowerShell — watch if AV kills it.
    Returns (page_accessible, status_code, block_reason, escalation_dict).
    """
    import subprocess
    url = f"{phish_url}?rid={rid}"
    print(f"[GoPhish] Simulating click: {url}")
    escalation = {'level_0_html': None, 'level_1_ps1': None,
                  'level_2_execute': None, 'triggered_level': None}

    # Fetch page
    try:
        req = urllib.request.Request(url)
        req.add_header('User-Agent',
                       'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                       'AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36')
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_make_plain_ssl()) as resp:
            body        = resp.read().decode('utf-8', errors='replace')
            http_status = resp.status
        print(f"[GoPhish]   -> HTTP {http_status} — {len(body)} bytes.")
    except urllib.error.HTTPError as e:
        return True, e.code, "", escalation
    except urllib.error.URLError as e:
        return False, 0, str(e.reason), escalation
    except OSError as e:
        return False, 0, str(e), escalation

    # Level 0 — .html drop
    print("[GoPhish] [L0] Dropping .html payload …")
    tmp0 = tempfile.NamedTemporaryFile(mode='w', suffix='.html',
                                       prefix='phish_page_', delete=False, encoding='utf-8')
    tmp0.write(body); tmp0.close()
    print(f"[GoPhish]   -> {tmp0.name}  (polling {_POLL_WINDOW}s)")
    q, t = _av_poll(tmp0.name)
    if q:
        escalation.update({'level_0_html': {'detected': True, 'latency_s': t}, 'triggered_level': 0})
        print(f"[GoPhish] [L0] DETECTED — quarantined in {t}s!")
        return False, http_status, "AV quarantined .html payload (L0)", escalation
    escalation['level_0_html'] = {'detected': False}
    try: os.unlink(tmp0.name)
    except OSError: pass
    print("[GoPhish] [L0] Not detected → escalating to L1 …")

    # Level 1 — .ps1 extension
    print("[GoPhish] [L1] Dropping .ps1 payload …")
    tmp1 = tempfile.NamedTemporaryFile(mode='w', suffix='.ps1',
                                       prefix='phish_drop_', delete=False, encoding='utf-8')
    tmp1.write(f"# AV-Benchmark phishing payload\n# {phish_url}\n\n{body}"); tmp1.close()
    print(f"[GoPhish]   -> {tmp1.name}  (polling {_POLL_WINDOW}s)")
    q, t = _av_poll(tmp1.name)
    if q:
        escalation.update({'level_1_ps1': {'detected': True, 'latency_s': t}, 'triggered_level': 1})
        print(f"[GoPhish] [L1] DETECTED — .ps1 quarantined in {t}s!")
        return False, http_status, "AV quarantined .ps1 payload (L1)", escalation
    escalation['level_1_ps1'] = {'detected': False}
    print("[GoPhish] [L1] Not detected → escalating to L2 …")

    # Level 2 — Active execution
    print("[GoPhish] [L2] Detonating .ps1 via PowerShell …")
    exec_r = {'detected': False, 'latency_s': None, 'note': ''}
    try:
        proc = subprocess.Popen(
            ['powershell.exe', '-NonInteractive', '-WindowStyle', 'Hidden',
             '-ExecutionPolicy', 'Bypass', '-File', tmp1.name],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 2.0; killed = False
        while time.monotonic() < deadline:
            ret = proc.poll()
            if (ret is not None and ret not in (0, None)) or not os.path.exists(tmp1.name):
                killed = True; break
            time.sleep(_POLL_INTERVAL)
        e2 = round(2.0 - max(0.0, deadline - time.monotonic()), 2)
        if killed:
            exec_r = {'detected': True, 'latency_s': e2, 'note': 'process killed/file deleted'}
            escalation.update({'level_2_execute': exec_r, 'triggered_level': 2})
            print(f"[GoPhish] [L2] DETECTED — killed in {e2}s!")
            try: proc.kill()
            except Exception: pass
            try: os.unlink(tmp1.name)
            except OSError: pass
            return False, http_status, "AV terminated executed payload (L2)", escalation
        exec_r['note'] = 'Ran 2s unchallenged'
        print("[GoPhish] [L2] Not detected — AV did not intervene.")
        try: proc.kill()
        except Exception: pass
    except Exception as ex:
        exec_r = {'detected': True, 'latency_s': 0, 'note': f'launch blocked: {ex}'}
        escalation.update({'level_2_execute': exec_r, 'triggered_level': 2})
        print(f"[GoPhish] [L2] DETECTED — launch blocked by AV: {ex}")
        try: os.unlink(tmp1.name)
        except OSError: pass
        return False, http_status, f"AV blocked PS launch (L2): {ex}", escalation
    finally:
        try: os.unlink(tmp1.name)
        except OSError: pass

    escalation['level_2_execute'] = exec_r
    print("[GoPhish] All levels (L0–L2) passed without AV detection.")
    return True, http_status, "", escalation



def _powershell_lol_test(phish_url):
    """
    Level 3 — Living-off-the-Land: use PowerShell Invoke-WebRequest to
    download the phishing payload. AV/AMSI monitors PS commands heavily.
    Returns (blocked: bool, detail: str, latency_s: float | None)
    """
    import subprocess
    print("[GoPhish] [L3-LoL] Running PowerShell IWR download test …")
    ps_tmp = os.path.join(tempfile.gettempdir(),
                          f"lol_phish_{int(time.time())}.html")
    cmd = (
        f"$ProgressPreference='SilentlyContinue'; "
        f"Invoke-WebRequest -Uri '{phish_url}' "
        f"-OutFile '{ps_tmp}' -UseBasicParsing"
    )
    try:
        result = subprocess.run(
            ['powershell.exe', '-NonInteractive', '-WindowStyle', 'Hidden',
             '-ExecutionPolicy', 'Bypass', '-Command', cmd],
            capture_output=True, text=True, timeout=15
        )
        stderr = result.stderr.strip()
        if result.returncode != 0:
            detail = f"IWR failed (rc={result.returncode}): {stderr[:300]}"
            print(f"[GoPhish] [L3] DETECTED — {detail}")
            return True, detail, 0.0
        if os.path.exists(ps_tmp):
            q, t = _av_poll(ps_tmp)
            if q:
                detail = f"AV quarantined PowerShell-downloaded file in {t}s"
                print(f"[GoPhish] [L3] DETECTED — {detail}")
                return True, detail, t
            try: os.unlink(ps_tmp)
            except OSError: pass
            print("[GoPhish] [L3] Not detected — IWR file survived poll window.")
            return False, "PowerShell IWR not blocked", None
        else:
            detail = "AV prevented PS download from writing to disk"
            print(f"[GoPhish] [L3] DETECTED — {detail}")
            return True, detail, 0.0
    except subprocess.TimeoutExpired:
        detail = "PowerShell IWR timed out (possible AV hang)"
        print(f"[GoPhish] [L3] DETECTED (timeout) — {detail}")
        return True, detail, None
    except Exception as ex:
        print(f"[GoPhish] [L3] Error: {ex}")
        return False, str(ex), None


def _simulate_credential_submit(phish_url, rid, timeout=10):
    """
    Simulate a victim submitting credentials on the phishing page.
    POST fake username/password to the GoPhish landing page.
    Returns (success:bool, status_code:int)
    """
    url  = f"{phish_url}?rid={rid}"
    data = urllib.parse.urlencode({
        'username': 'benchmark_test_user',
        'password': 'benchmark_test_pass',
        'email':    'test@benchmark.local',
    }).encode('utf-8')
    print(f"[GoPhish] Simulating credential submit to: {url}")
    try:
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('User-Agent',
                       'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                       'AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36')
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_make_plain_ssl()) as resp:
            print(f"[GoPhish]   -> Credential submit HTTP {resp.status}")
            return True, resp.status
    except Exception as e:
        print(f"[GoPhish]   -> Credential submit error: {e}")
        return False, 0


# ---------------------------------------------------------------------------
# The Module
# ---------------------------------------------------------------------------

class GoPhishModule(BaseModule):
    """GoPhish phishing simulation — direct AV interaction via HTTP."""

    def __init__(self):
        super().__init__()
        self.name            = "GoPhish Simulation"
        self.description     = ("Phishing simulation: creates a GoPhish campaign, "
                                "then this machine directly accesses the phishing URL "
                                "to test if AV/SmartScreen blocks it.")
        self.detected        = False
        self.gophish_results = {}
        self.offline_demo    = False
        self._config         = self._load_config()

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def _load_config(self):
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'gophish_config.json'
        )
        defaults = {
            "host":                    "http://127.0.0.1:3333",
            "api_key":                 "",
            "campaign_name":           "AV_Benchmark_Test",
            "smtp_profile":            "",
            "email_template":          "",
            "landing_page":            "",
            "phish_port":              8081,
            "simulate_cred_submit":    True,
            "offline_demo_mode":       False,
        }
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    loaded = json.load(f)
                defaults.update(loaded)
                print(f"[GoPhish] Config: {config_path}")
                print(f"[GoPhish] Host: {defaults['host']}  "
                      f"| offline_demo: {defaults['offline_demo_mode']}  "
                      f"| api_key set: {bool(defaults['api_key'].strip())}")
            except Exception as e:
                print(f"[GoPhish] Could not load config: {e}")
        else:
            print(f"[GoPhish] WARNING: config not found at {config_path}")
        return defaults

    def get_info(self):
        return {'id': self.module_id, 'name': self.name, 'description': self.description}

    # ------------------------------------------------------------------
    # Offline demo fallback
    # ------------------------------------------------------------------

    def _run_offline_demo(self, monitor, start_time, reason=""):
        import random
        print(f"[GoPhish] OFFLINE DEMO MODE" + (f" ({reason})" if reason else ""))
        time.sleep(2)
        if monitor.monitoring:
            monitor.stop()
        self.offline_demo    = True
        self.detected        = False
        self.gophish_results = {
            'mode':                  'Demo',
            'campaign_id':           'DEMO',
            'campaign_status':       'Completed (Demo)',
            'emails_sent':           1,
            'phish_url_accessible':  True,
            'phish_page_blocked':    False,
            'cred_submit_success':   True,
            'clicks_recorded':       random.randint(0, 1),
            'submitted_recorded':    0,
        }
        self.execution_time = time.time() - start_time
        self.metrics        = monitor.get_results()
        self.status         = "Completed (Demo)"

    # ------------------------------------------------------------------
    # Live run
    # ------------------------------------------------------------------

    def _run_live(self, monitor, start_time):
        cfg    = self._config
        client = GoPhishClient(cfg['host'], cfg['api_key'])

        # -- 1. Connect --
        print(f"[GoPhish] Connecting to {cfg['host']} ...")
        if not client.ping():
            print(f"[GoPhish] Cannot reach server at {cfg['host']}")
            return False
        print("[GoPhish] Connected OK")

        # -- 2. Resolve resources --
        smtp_list = client.get_smtp_profiles()
        tpl_list  = client.get_templates()
        page_list = client.get_pages()
        print(f"[GoPhish] Resources: {len(smtp_list)} SMTP, "
              f"{len(tpl_list)} templates, {len(page_list)} pages")

        smtp = _by_name(smtp_list, cfg['smtp_profile'])
        tpl  = _by_name(tpl_list,  cfg['email_template'])
        page = _by_name(page_list, cfg['landing_page'])

        missing = []
        if not smtp:
            missing.append(f"SMTP '{cfg['smtp_profile']}' "
                           f"(available: {[s.get('name') for s in smtp_list]})")
        if not tpl:
            missing.append(f"Template '{cfg['email_template']}' "
                           f"(available: {[t.get('name') for t in tpl_list]})")
        if not page:
            missing.append(f"Page '{cfg['landing_page']}' "
                           f"(available: {[p.get('name') for p in page_list]})")
        if missing:
            print("[GoPhish] Missing resources:")
            for m in missing:
                print(f"  - {m}")
            return False

        # -- 3. Build phishing URL (used for direct simulation) --
        try:
            host_ip   = cfg['host'].split('://')[-1].split(':')[0]
            phish_url = f"http://{host_ip}:{cfg.get('phish_port', 8081)}"
        except Exception:
            phish_url = cfg['host']
        print(f"[GoPhish] Phishing server URL: {phish_url}")

        # -- 4. Create target group (one fake target) --
        group_name = f"BM_Group_{int(time.time())}"
        group_data = client.create_group(group_name, [{
            'first_name': 'Test',
            'last_name':  'Target',
            'email':      'benchmark@av-test.local',
            'position':   'Benchmark Target',
        }])
        group_id = group_data.get('id')
        if not group_id:
            print("[GoPhish] Failed to create target group")
            return False
        print(f"[GoPhish] Group '{group_name}' created (id={group_id})")

        # -- 5. Create campaign --
        launch_dt   = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=3)
        launch_time = launch_dt.strftime('%Y-%m-%dT%H:%M:%S+00:00')
        campaign_name = f"{cfg['campaign_name']}_{int(time.time())}"

        payload = {
            'name':        campaign_name,
            'template':    {'name': tpl['name'], 'id': tpl.get('id', 0)},
            'page':        {'name': page['name'], 'id': page.get('id', 0)},
            'smtp':        {'name': smtp['name'], 'id': smtp.get('id', 0)},
            'launch_date': launch_time,
            'url':         phish_url,
            'groups':      [{'name': group_name}],
        }
        print(f"[GoPhish] Creating campaign '{campaign_name}'...")
        camp_data = client.create_campaign(payload)
        camp_id   = camp_data.get('id')
        if not camp_id or camp_id < 0:
            print(f"[GoPhish] Campaign creation failed: {camp_data}")
            client.delete_group(group_id)
            return False
        print(f"[GoPhish] Campaign created (id={camp_id})")

        # -- 6. Wait for campaign launch + get tracking RId --
        print("[GoPhish] Waiting 8s for campaign to launch and tracking IDs to be assigned...")
        time.sleep(8)

        results_data = client.get_campaign_results(camp_id)
        rids         = _get_rids(results_data)
        print(f"[GoPhish] Recipient tracking IDs: {rids}")

        if not rids:
            # GoPhish may not have assigned RIds yet — use campaign ID as fallback
            rids = [str(camp_id)]
            print("[GoPhish] No RIds yet — using campaign ID as fallback rid")

        # =================================================================
        # 7. DIRECT SIMULATION: this Windows machine accesses the phishing
        #    URL — Windows Defender SmartScreen / network protection will
        #    intercept this if it detects a phishing/malicious site.
        # =================================================================
        print("\n[GoPhish] ---- AV INTERACTION TEST ----")
        print("[GoPhish] This machine will now access the phishing URL.")
        print("[GoPhish] Windows Defender SmartScreen / AV web filter")
        print("[GoPhish] will intercept this if phishing is detected.")
        print("[GoPhish] ----------------------------------------")

        click_success      = False
        click_code         = 0
        block_reason       = ""
        submit_success     = False
        escalation_summary = {}
        lol_blocked        = False
        lol_detail         = 'not run'
        lol_latency        = None

        for rid in rids:
            ok, code, reason, esc_detail = _simulate_click(phish_url, rid)
            if ok:
                click_success = True
                click_code    = code
            else:
                block_reason  = reason
            escalation_summary = esc_detail   # keep last result

        # Simulate credential submission if click succeeded
        if click_success and cfg.get('simulate_cred_submit', True):
            print("[GoPhish] Phishing page loaded — now simulating credential submission...")
            for rid in rids:
                sub_ok, sub_code = _simulate_credential_submit(phish_url, rid)
                if sub_ok:
                    submit_success = True

        # -- 7b. Level 3 — Living-off-the-Land PowerShell test (always runs) --
        print("\n[GoPhish] ---- LEVEL 3: POWERSHELL LOL TEST ----")
        lol_blocked, lol_detail, lol_latency = _powershell_lol_test(phish_url)

        print("\n[GoPhish] ---- SIMULATION COMPLETE ----")

        # -- 8. Wait a moment then read GoPhish tracking results --
        print("[GoPhish] Waiting 5s for GoPhish to record events...")
        time.sleep(5)

        final_data = client.get_campaign_results(camp_id)
        camp_status = final_data.get('status', 'Unknown')
        sent, opened, clicked, submitted, reported = _count_results(final_data)

        print(f"[GoPhish] Campaign status : {camp_status}")
        print(f"[GoPhish] Emails sent     : {sent}")
        print(f"[GoPhish] Clicks recorded : {clicked}")
        print(f"[GoPhish] Submits recorded: {submitted}")

        # -- 9. Detection verdict --
        # A detection at ANY escalation level counts as DETECTED.
        any_escalation_detected = (
            (escalation_summary.get('triggered_level') is not None)
            or lol_blocked
        )
        self.detected = (not click_success) or any_escalation_detected

        if not click_success and escalation_summary.get('triggered_level') is None and not lol_blocked:
            verdict_reason = f"Phishing URL was BLOCKED at network level: {block_reason}"
        elif any_escalation_detected:
            trig = escalation_summary.get('triggered_level')
            level_labels = {
                0: 'L0 — on-disk .html quarantine',
                1: 'L1 — .ps1 heuristic quarantine',
                2: 'L2 — PowerShell execution terminated',
            }
            level_label = (
                level_labels.get(trig, f'Level {trig}') if trig is not None
                else 'L3 — PowerShell LoL (IWR) blocked'
            )
            verdict_reason = (
                f"Detected via {level_label}. "
                f"{block_reason or lol_detail}"
            )
        else:
            verdict_reason = (
                f"Phishing page loaded (HTTP {click_code}). "
                f"{'Credentials submitted.' if submit_success else ''} "
                "All escalation levels passed without AV detection."
            )
        print(f"[GoPhish] VERDICT: {'DETECTED' if self.detected else 'NOT DETECTED'}")
        print(f"[GoPhish] Reason : {verdict_reason}")
        print(f"[GoPhish] Escalation summary:")
        print(f"  L0 (.html drop) : {escalation_summary.get('level_0_html')}")
        print(f"  L1 (.ps1 ext)   : {escalation_summary.get('level_1_ps1')}")
        print(f"  L2 (execution)  : {escalation_summary.get('level_2_execute')}")
        print(f"  L3 (PS LoL)     : blocked={lol_blocked}  detail={lol_detail}")

        # -- 10. Mark campaign complete (preserve for archive — do NOT delete) --
        # Campaigns and groups are intentionally kept in GoPhish so the
        # evidence trail (clicks, submits, timeline) is visible in the
        # admin UI. Delete them manually if needed.
        client.complete_campaign(camp_id)
        print(f"[GoPhish] Campaign {camp_id} marked complete — preserved in GoPhish archive.")
        print(f"[GoPhish] Group '{group_name}' (id={group_id}) preserved — delete manually if needed.")

        self.gophish_results = {
            'mode':                  'Live',
            'campaign_id':           camp_id,
            'campaign_status':       camp_status,
            'phish_url':             phish_url,
            'phish_url_accessible':  click_success,
            'phish_page_blocked':    not click_success,
            'block_reason':          block_reason,
            'cred_submit_success':   submit_success,
            'clicks_recorded':       clicked,
            'submitted_recorded':    submitted,
            'verdict_reason':        verdict_reason,
            # Escalation detail (for dashboard modal)
            'escalation': {
                'level_0_html':    escalation_summary.get('level_0_html'),
                'level_1_ps1':     escalation_summary.get('level_1_ps1'),
                'level_2_execute': escalation_summary.get('level_2_execute'),
                'triggered_level': escalation_summary.get('triggered_level'),
                'level_3_lol': {
                    'blocked':    lol_blocked,
                    'detail':     lol_detail,
                    'latency_s':  lol_latency,
                },
            },
        }

        if monitor.monitoring:
            monitor.stop()
        self.execution_time = time.time() - start_time
        self.metrics        = monitor.get_results()
        self.status         = "Completed"
        return True

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self, monitor: SystemMonitor) -> bool:
        start_time = time.time()
        try:
            self.status = "Running"
            monitor.start()

            cfg = self._config
            use_demo = (
                cfg.get('offline_demo_mode', False)
                or not cfg.get('api_key', '').strip()
                or cfg.get('api_key', '') in ('YOUR_API_KEY_HERE', '')
            )

            if use_demo:
                self._run_offline_demo(monitor, start_time,
                                       reason="offline_demo_mode=true or no API key")
                return True

            try:
                ok = self._run_live(monitor, start_time)
            except Exception as live_err:
                print(f"[GoPhish] Live run error: {type(live_err).__name__}: {live_err}")
                import traceback
                traceback.print_exc()
                ok = False

            if not ok:
                print("[GoPhish] Falling back to offline demo mode")
                if monitor.monitoring:
                    monitor.stop()
                import copy
                from system_monitor import SystemMonitor as SM
                m2 = SM()
                m2.start()
                self._run_offline_demo(m2, start_time, reason="live run failed")

            return True

        except Exception as e:
            print(f"[GoPhish] FATAL: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            self.status = "Failed"
            try:
                if monitor.monitoring:
                    monitor.stop()
            except Exception:
                pass
            self.execution_time = time.time() - start_time
            self.metrics        = monitor.get_results()
            return False

    def get_results(self):
        return {
            'module_id':       self.module_id,
            'name':            self.name,
            'execution_time':  round(self.execution_time, 2),
            'status':          self.status,
            'detected':        self.detected,
            'offline_demo':    self.offline_demo,
            'gophish_results': self.gophish_results,
            'metrics':         self.metrics,
        }
