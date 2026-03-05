"""
Module 1: EICAR Test
Generates EICAR test file and monitors for antivirus detection.

Detection strategy:
  1. Check BEFORE write - if baseline file check passes
  2. Write EICAR string
  3. Immediately poll file existence and content every 50ms for up to 10s
  4. Also handles the case where WD quarantines so fast the file
     never appears (detected = True if write succeeded but file is
     already gone on first check).
"""

import os
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_module import BaseModule
from system_monitor import SystemMonitor


# Split EICAR string so our own AV doesn't flag this source file
_P1 = r'X5O!P%@AP[4\PZX54(P^)7CC)7}'
_P2 = r'$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
EICAR_STRING = _P1 + _P2


class EICARModule(BaseModule):
    """EICAR antivirus test module"""

    def __init__(self):
        super().__init__()
        self.name = "EICAR Test"
        self.description = "Standard antivirus detection test using EICAR test file"
        self.test_file_path = None
        self.detected = False
        self.detection_verdict = "NOT DETECTED"
        self.detection_notes = ""

    def get_info(self) -> dict:
        return {
            'id': self.module_id,
            'name': self.name,
            'description': self.description
        }

    def _file_is_neutralised(self, path: str) -> bool:
        """
        Return True if AV has neutralised the file:
        - File no longer exists (quarantined / deleted), OR
        - File exists but content no longer matches EICAR string (wiped)
        """
        if not os.path.exists(path):
            return True   # Deleted / quarantined

        try:
            with open(path, 'r', errors='replace') as f:
                content = f.read()
            # Content wiped or replaced by AV
            if EICAR_STRING not in content:
                return True
        except (PermissionError, OSError):
            # AV locked / quarantined the file - counts as detected
            return True

        return False

    def run(self, monitor: SystemMonitor) -> bool:
        try:
            start_time = time.time()
            self.status = "Running"

            monitor.start()

            # --- Prepare temp dir ---
            # IMPORTANT: Write to the SYSTEM temp directory, NOT inside the
            # project folder. The project folder is typically whitelisted in
            # the AV settings (so the tool itself isn't quarantined), which
            # means the AV would never scan a file placed there — defeating
            # the whole purpose of the EICAR test.
            # Using %TEMP% ensures the AV's real-time scanner sees the file.
            temp_dir = os.environ.get('TEMP', os.environ.get('TMP', os.path.join(
                os.path.dirname(os.path.abspath(__file__)), 'temp'
            )))
            os.makedirs(temp_dir, exist_ok=True)
            self.test_file_path = os.path.join(temp_dir, 'eicar_test.txt')

            # --- Remove any stale file from previous run ---
            if os.path.exists(self.test_file_path):
                try:
                    os.remove(self.test_file_path)
                except Exception:
                    pass
                time.sleep(0.1)

            print(f"[EICAR] Writing test file: {self.test_file_path}")

            # --- Write EICAR string ---
            write_succeeded = False
            try:
                with open(self.test_file_path, 'w') as f:
                    f.write(EICAR_STRING)
                write_succeeded = True
                print("[EICAR] File written. Monitoring for AV detection...")
            except PermissionError:
                # Some AVs block the write itself — that IS a detection
                print("[EICAR] Write was blocked by AV (PermissionError)")
                self.detected = True
                self.detection_verdict = "DETECTED"
                self.detection_notes = (
                    "AV blocked the file write operation itself (PermissionError)"
                )
                monitor.mark_detection()

            if write_succeeded:
                # --- Immediate check: WD can quarantine within <100ms ---
                # Check right away before first sleep
                if self._file_is_neutralised(self.test_file_path):
                    elapsed_at_detect = time.time() - start_time
                    self.detected = True
                    self.detection_verdict = "DETECTED"
                    self.detection_notes = (
                        "AV removed or neutralised the EICAR file (near-instant)"
                    )
                    monitor.mark_detection()
                    print(f"[EICAR] Detection confirmed immediately "
                          f"({elapsed_at_detect:.2f}s)")

                else:
                    # --- Poll loop: 50ms interval, 10s max ---
                    detection_window = 10.0
                    check_interval   = 0.05   # 50ms — fast enough to catch WD
                    elapsed          = 0.0

                    while elapsed < detection_window and not self.detected:
                        time.sleep(check_interval)
                        elapsed += check_interval

                        if self._file_is_neutralised(self.test_file_path):
                            elapsed_at_detect = time.time() - start_time
                            self.detected = True
                            self.detection_verdict = "DETECTED"
                            self.detection_notes = (
                                f"AV removed/neutralised EICAR file "
                                f"at {elapsed:.2f}s into polling"
                            )
                            monitor.mark_detection()
                            print(f"[EICAR] Detection confirmed at "
                                  f"{elapsed_at_detect:.2f}s")
                            break

                    if not self.detected:
                        self.detection_verdict = "NOT DETECTED"
                        self.detection_notes = (
                            "EICAR file survived full 10s detection window. "
                            "Real-time protection may be disabled."
                        )
                        print("[EICAR] No detection within 10s window")

            # --- Stop monitoring ---
            monitor.stop()

            # --- Cleanup ---
            if os.path.exists(self.test_file_path):
                try:
                    os.remove(self.test_file_path)
                    print("[EICAR] Test file cleaned up")
                except Exception:
                    print("[EICAR] Note: File already quarantined (cannot remove)")

            self.execution_time = time.time() - start_time
            self.metrics = monitor.get_results()
            self.status = "Completed"
            return True

        except Exception as e:
            print(f"[EICAR] Unexpected error: {e}")
            self.status = "Failed"
            self.detection_verdict = "ERROR"
            self.detection_notes = str(e)
            try:
                monitor.stop()
            except Exception:
                pass
            self.execution_time = time.time() - start_time
            self.metrics = monitor.get_results()
            return False

    def get_results(self) -> dict:
        return {
            'module_id':          self.module_id,
            'name':               self.name,
            'execution_time':     round(self.execution_time, 2),
            'status':             self.status,
            'detected':           self.detected,
            'detection_verdict':  self.detection_verdict,
            'detection_notes':    self.detection_notes,
            'metrics':            self.metrics,
        }
