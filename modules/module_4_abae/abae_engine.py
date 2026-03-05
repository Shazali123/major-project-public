"""
ABAE Engine — Adaptive Behavioral Anomaly Engine
=================================================
All behavioral test logic lives here.

Architecture
------------
BehaviorResult  dataclass  — output of one test run
ABAEEngine      class      — owns the sandbox, runs all 5 tests,
                             returns list[BehaviorResult]

Detection philosophy
--------------------
We never call AV APIs.  We observe OS-level side-effects of AV
intervention:
    - PermissionError / OSError on a file write   → AV locked the file
    - WindowsError on a registry write             → registry monitor blocked it
    - Subprocess exit code / launch failure        → AV killed the child process
    - File missing / zero-bytes after write        → real-time scanner quarantined it

All tests run inside a throw-away sandbox directory (BME_TEST/) that is
wiped in a finally block even if the AV terminates the parent process.
"""

import os
import sys
import time
import math
import winreg
import random
import string
import tempfile
import subprocess
import threading
import shutil
import json
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class BehaviorResult:
    tid:               str            # e.g. "B-01"
    name:              str
    detected:          bool  = False
    detection_latency: float = 0.0   # seconds from test start to first block
    detail:            str   = ""
    elapsed:           float = 0.0
    extra:             dict  = field(default_factory=dict)  # test-specific metrics


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (bits per byte) of a byte sequence."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _random_str(length: int) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=length))


def _run_proc(args, timeout=10):
    """Run subprocess; return (rc, stdout, stderr). rc=-1 means launch failed."""
    try:
        p = subprocess.run(
            args,
            capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -2, "", "TIMEOUT"
    except (FileNotFoundError, PermissionError, OSError) as e:
        return -1, "", str(e)
    except Exception as e:
        return -1, "", str(e)


# ---------------------------------------------------------------------------
# Individual behavioral tests
# ---------------------------------------------------------------------------

def _b01_file_manipulation(sandbox: str, cfg: dict) -> BehaviorResult:
    """
    B-01 — Rapid File System Manipulation
    Creates N dummy files then rapidly overwrites / renames / touch-modifies
    them to simulate ransomware-like churning behaviour.
    """
    tid, name = "B-01", "Rapid File Manipulation"
    t0         = time.time()
    test_dir   = os.path.join(sandbox, "b01_files")
    os.makedirs(test_dir, exist_ok=True)

    n            = cfg.get("file_manipulation_count", 300)
    files_done   = 0
    detected     = False
    detail       = ""
    detect_lat   = 0.0

    try:
        # Phase 1: create files
        paths = []
        for i in range(n):
            p = os.path.join(test_dir, f"bm_{i:04d}.tmp")
            with open(p, "w") as f:
                f.write(_random_str(64))
            paths.append(p)

        # Phase 2: rapid overwrite with random content
        for i, p in enumerate(paths):
            try:
                with open(p, "wb") as f:
                    f.write(os.urandom(128))
                files_done += 1
            except (PermissionError, OSError) as e:
                detected    = True
                detect_lat  = time.time() - t0
                detail      = f"Write blocked at file {i} by OS/AV: {e}"
                break

        if not detected:
            # Phase 3: rename with random extension (mimics ransomware extension swap)
            for i, p in enumerate(paths):
                try:
                    new_p = p + ".rnd"
                    os.rename(p, new_p)
                    files_done += 1
                except (PermissionError, OSError) as e:
                    detected   = True
                    detect_lat = time.time() - t0
                    detail     = f"Rename blocked at file {i} by OS/AV: {e}"
                    break

        if not detected:
            detail = f"All {n} files written and renamed without AV block"

    except (PermissionError, OSError) as e:
        detected   = True
        detect_lat = time.time() - t0
        detail     = f"Directory/file operation blocked: {e}"
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

    return BehaviorResult(
        tid=tid, name=name, detected=detected,
        detection_latency=round(detect_lat, 3),
        detail=detail,
        elapsed=round(time.time() - t0, 2),
        extra={"files_modified_before_detection": files_done},
    )


def _b02_entropy_spike(sandbox: str, cfg: dict) -> BehaviorResult:
    """
    B-02 — Entropy Spike Simulation
    Writes high-entropy (os.urandom) data into N files and computes the
    Shannon entropy delta to confirm the spike, then checks if AV blocked.
    """
    tid, name = "B-02", "Entropy Spike Simulation"
    t0        = time.time()
    test_dir  = os.path.join(sandbox, "b02_entropy")
    os.makedirs(test_dir, exist_ok=True)

    n           = cfg.get("entropy_file_count", 50)
    threshold   = cfg.get("entropy_high_threshold", 7.5)
    detected    = False
    detect_lat  = 0.0
    detail      = ""
    avg_entropy = 0.0
    files_done  = 0

    try:
        entropies = []
        for i in range(n):
            p = os.path.join(test_dir, f"ent_{i:03d}.bin")
            raw = os.urandom(4096)   # truly random → max entropy
            try:
                with open(p, "wb") as f:
                    f.write(raw)
                entropies.append(_shannon_entropy(raw))
                files_done += 1
            except (PermissionError, OSError) as e:
                detected   = True
                detect_lat = time.time() - t0
                detail     = f"High-entropy write blocked at file {i}: {e}"
                break

        if entropies:
            avg_entropy = round(sum(entropies) / len(entropies), 4)

        if not detected:
            if avg_entropy >= threshold:
                # Files were written — AV did NOT block the entropy spike
                detail = (f"Avg entropy {avg_entropy} bits/byte (≥ {threshold} threshold). "
                          f"AV did not block high-entropy writes.")
            else:
                detail = f"Avg entropy {avg_entropy} bits/byte — below threshold."

    except (PermissionError, OSError) as e:
        detected   = True
        detect_lat = time.time() - t0
        detail     = f"Entropy test blocked at OS level: {e}"
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

    return BehaviorResult(
        tid=tid, name=name, detected=detected,
        detection_latency=round(detect_lat, 3),
        detail=detail,
        elapsed=round(time.time() - t0, 2),
        extra={"avg_entropy_bits": avg_entropy,
               "files_written": files_done,
               "entropy_threshold": threshold},
    )


def _b03_process_burst(sandbox: str, cfg: dict) -> BehaviorResult:
    """
    B-03 — Suspicious Process Burst Activity
    Spawns multiple rapid short-lived subprocesses then performs a
    high-frequency file-open/close burst — mimics malicious execution chains.
    """
    tid, name = "B-03", "Process Burst Activity"
    t0        = time.time()
    test_dir  = os.path.join(sandbox, "b03_burst")
    os.makedirs(test_dir, exist_ok=True)

    n_proc     = cfg.get("process_burst_count", 20)
    interval   = cfg.get("process_burst_interval_s", 0.04)
    n_ops      = cfg.get("file_burst_ops", 1000)
    detected   = False
    detect_lat = 0.0
    procs_done = 0
    detail     = ""

    try:
        # Phase 1: rapid subprocess spawning
        for i in range(n_proc):
            rc, _, stderr = _run_proc(
                ["cmd", "/c", f"echo ABAE_BURST_{i}"], timeout=5
            )
            if rc == -1:
                detected   = True
                detect_lat = time.time() - t0
                detail     = f"Process spawn blocked at iteration {i}: {stderr}"
                break
            procs_done += 1
            time.sleep(interval)

        if not detected:
            # Phase 2: high-frequency file open/close (I/O storm)
            burst_file = os.path.join(test_dir, "burst_io.tmp")
            for i in range(n_ops):
                try:
                    with open(burst_file, "w") as f:
                        f.write(str(i))
                except (PermissionError, OSError) as e:
                    detected   = True
                    detect_lat = time.time() - t0
                    detail     = f"File I/O burst blocked at op {i}: {e}"
                    break

        if not detected:
            detail = (f"{procs_done}/{n_proc} processes spawned, "
                      f"{n_ops} file I/O ops completed without AV block.")

    except (PermissionError, OSError) as e:
        detected   = True
        detect_lat = time.time() - t0
        detail     = f"Burst activity blocked: {e}"
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

    return BehaviorResult(
        tid=tid, name=name, detected=detected,
        detection_latency=round(detect_lat, 3),
        detail=detail,
        elapsed=round(time.time() - t0, 2),
        extra={"processes_spawned": procs_done,
               "processes_target": n_proc},
    )


def _b04_registry_modification(cfg: dict) -> BehaviorResult:
    """
    B-04 — Registry Modification Attempt (non-destructive)
    Writes a benign test value to HKCU\\Software\\ABAE_BenchmarkTest,
    reads it back to verify, then deletes it.
    Operates entirely in user-space (HKCU) — no admin rights needed.
    """
    tid, name  = "B-04", "Registry Modification Attempt"
    t0         = time.time()
    key_path   = r"Software\ABAE_BenchmarkTest"
    val_name   = "abae_test_marker"
    val_data   = f"ABAE_RUN_{int(t0)}"
    detected   = False
    detect_lat = 0.0
    detail     = ""
    reg_ok     = False

    try:
        # Create / open key
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        # Write value
        winreg.SetValueEx(key, val_name, 0, winreg.REG_SZ, val_data)
        # Read back
        read_val, _ = winreg.QueryValueEx(key, val_name)
        reg_ok = (read_val == val_data)
        winreg.DeleteValue(key, val_name)
        winreg.CloseKey(key)
        # Delete the key itself
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)

        if reg_ok:
            detail = "Registry write/read/delete completed — AV registry monitor did not intervene."
        else:
            detected   = True
            detect_lat = time.time() - t0
            detail     = "Registry value read-back mismatch — possible AV redirection/block."

    except (PermissionError, OSError) as e:
        detected   = True
        detect_lat = time.time() - t0
        detail     = f"Registry operation blocked by OS/AV: {e}"
    except Exception as e:
        detected   = True
        detect_lat = time.time() - t0
        detail     = f"Registry operation raised unexpected exception: {e}"

    return BehaviorResult(
        tid=tid, name=name, detected=detected,
        detection_latency=round(detect_lat, 3),
        detail=detail,
        elapsed=round(time.time() - t0, 2),
        extra={"registry_op_success": reg_ok},
    )


def _b05_behavioral_consistency(sandbox: str, cfg: dict) -> BehaviorResult:
    """
    B-05 — Behavioral Consistency
    Re-runs B-01, B-02, and B-03 three times with slight parameter
    variations (±10% file count, different random seed).
    Purpose: detect whether AV learns/adapts or only reacts on first exposure.
    """
    tid, name  = "B-05", "Behavioral Consistency"
    t0         = time.time()
    runs       = cfg.get("behavioral_consistency_runs", 3)
    base_files = cfg.get("file_manipulation_count", 300)
    base_ent   = cfg.get("entropy_file_count", 50)

    run_detections = []
    detail_parts   = []

    for run_idx in range(runs):
        # Vary parameters slightly each run
        variation   = 1.0 + random.uniform(-0.10, 0.10)
        run_cfg     = dict(cfg)
        run_cfg["file_manipulation_count"] = max(10, int(base_files * variation))
        run_cfg["entropy_file_count"]      = max(5,  int(base_ent   * variation))
        # Reduce burst to keep the sub-test fast
        run_cfg["process_burst_count"] = 5
        run_cfg["file_burst_ops"]      = 100

        run_sandbox = os.path.join(sandbox, f"b05_run{run_idx}")
        os.makedirs(run_sandbox, exist_ok=True)

        r1 = _b01_file_manipulation(run_sandbox, run_cfg)
        r2 = _b02_entropy_spike(run_sandbox, run_cfg)
        r3 = _b03_process_burst(run_sandbox, run_cfg)

        run_det = any([r1.detected, r2.detected, r3.detected])
        run_detections.append(run_det)
        detail_parts.append(
            f"Run {run_idx+1}: B01={'D' if r1.detected else 'N'}"
            f" B02={'D' if r2.detected else 'N'}"
            f" B03={'D' if r3.detected else 'N'}"
        )
        shutil.rmtree(run_sandbox, ignore_errors=True)

    n_det             = sum(1 for d in run_detections if d)
    consistency_score = f"{n_det}/{runs}"
    # Detected if AV was consistent across ALL runs (or majority)
    detected = n_det >= (runs // 2 + 1)

    return BehaviorResult(
        tid=tid, name=name, detected=detected,
        detection_latency=0.0,
        detail=f"Consistency: {consistency_score}. " + "  |  ".join(detail_parts),
        elapsed=round(time.time() - t0, 2),
        extra={"consistency_rate": consistency_score,
               "runs": runs,
               "detections_per_run": run_detections},
    )


# ---------------------------------------------------------------------------
# Engine orchestrator
# ---------------------------------------------------------------------------

class ABAEEngine:
    """
    Orchestrates all 5 behavioral tests inside an isolated sandbox directory.
    Call run_all() → list[BehaviorResult].
    """

    def __init__(self, cfg: dict):
        self.cfg     = cfg
        self.sandbox = os.path.abspath(cfg.get("sandbox_dir", "BME_TEST"))

    def _prepare_sandbox(self):
        shutil.rmtree(self.sandbox, ignore_errors=True)
        os.makedirs(self.sandbox, exist_ok=True)
        print(f"[ABAE] Sandbox prepared: {self.sandbox}")

    def _teardown_sandbox(self):
        shutil.rmtree(self.sandbox, ignore_errors=True)
        print(f"[ABAE] Sandbox cleaned up.")

    def run_all(self) -> list:
        """Run all 5 behavioral tests; always cleans up sandbox."""
        self._prepare_sandbox()
        results = []
        try:
            tests = [
                ("B-01", "Rapid File Manipulation",        lambda: _b01_file_manipulation(self.sandbox, self.cfg)),
                ("B-02", "Entropy Spike Simulation",       lambda: _b02_entropy_spike(self.sandbox, self.cfg)),
                ("B-03", "Process Burst Activity",         lambda: _b03_process_burst(self.sandbox, self.cfg)),
                ("B-04", "Registry Modification Attempt",  lambda: _b04_registry_modification(self.cfg)),
                ("B-05", "Behavioral Consistency",         lambda: _b05_behavioral_consistency(self.sandbox, self.cfg)),
            ]

            for tid, tname, func in tests:
                print(f"[ABAE] ---- {tid}: {tname} ----")
                try:
                    result = func()
                except Exception as e:
                    # Unexpected exception → treat as detection (AV killed something)
                    result = BehaviorResult(
                        tid=tid, name=tname, detected=True,
                        detail=f"Test raised exception (possible AV intervention): {e}",
                        elapsed=0.0,
                    )
                verdict = "DETECTED" if result.detected else "NOT DETECTED"
                print(f"[ABAE]   -> [{verdict}]  {result.elapsed}s  — {result.detail}")
                results.append(result)

        finally:
            self._teardown_sandbox()

        return results
