"""
Results Handler - Compiles and exports test results
"""

import os
import json
import uuid
import urllib.request
import urllib.error
from datetime import datetime
from typing import List, Dict

try:
    from score_calculator import calculate_scores
except ImportError:
    def calculate_scores(module_results):
        return {"detection_score": 0.0, "performance_score": 0.0,
                "physical_total": 0.0, "breakdown": {}}


class ResultsHandler:
    """Handles result compilation and export"""

    def __init__(self, results_dir: str = "results"):
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _verdict_line(detected: bool) -> str:
        if detected:
            return "  >>> VERDICT: [DETECTED] <<<"
        return "  >>> VERDICT: [NOT DETECTED] <<<"

    @staticmethod
    def _fmt_ram(mb: float) -> str:
        """Format RAM delta value nicely"""
        if mb < 1.0:
            return f"{round(mb * 1024, 1)} KB"
        return f"{round(mb, 2)} MB"

    # ------------------------------------------------------------------
    # EICAR section
    # ------------------------------------------------------------------

    def _format_eicar(self, result: dict, metrics: dict) -> List[str]:
        lines = []
        detected = result.get('detected', False)
        verdict = result.get('detection_verdict', 'UNKNOWN')
        notes = result.get('detection_notes', '')
        det_time = metrics.get('detection_time')

        lines.append(self._verdict_line(detected))

        if det_time is not None:
            lines.append(f"  Detection Time  : {det_time}s after file creation")
        else:
            lines.append("  Detection Time  : N/A (no detection within test window)")

        if notes:
            lines.append(f"  Notes           : {notes}")

        return lines

    # ------------------------------------------------------------------
    # GoPhish section
    # ------------------------------------------------------------------

    def _format_gophish(self, result: dict) -> List[str]:

        lines   = []
        gp      = result.get('gophish_results', {})
        offline = result.get('offline_demo', False)
        mode    = gp.get('mode', 'Demo' if offline else 'Live')
        detected = result.get('detected', False)

        if offline or mode == 'Demo':
            lines.append("  [OFFLINE DEMO MODE - GoPhish server not configured]")
            lines.append(self._verdict_line(detected))
            return lines

        # --- Live simulation results ---
        lines.append(self._verdict_line(detected))

        phish_url   = gp.get('phish_url', 'N/A')
        accessible  = gp.get('phish_url_accessible', False)
        blocked     = gp.get('phish_page_blocked', True)
        block_reason = gp.get('block_reason', '')
        cred_ok     = gp.get('cred_submit_success', False)
        clicks      = gp.get('clicks_recorded', 'N/A')
        submits     = gp.get('submitted_recorded', 'N/A')
        camp_id     = gp.get('campaign_id', 'N/A')
        camp_status = gp.get('campaign_status', 'N/A')
        verdict_rsn = gp.get('verdict_reason', '')

        lines.append(f"  Campaign ID       : {camp_id}")
        lines.append(f"  Campaign Status   : {camp_status}")
        lines.append(f"  Phishing URL      : {phish_url}")
        lines.append(f"  URL Accessible    : {'YES - page loaded' if accessible else 'NO - blocked/unreachable'}")
        if blocked and block_reason:
            lines.append(f"  Block Reason      : {block_reason}")
        lines.append(f"  Cred Submission   : {'Succeeded (data POSTed)' if cred_ok else 'Not submitted / blocked'}")
        lines.append(f"  Clicks Recorded   : {clicks}")
        lines.append(f"  Submits Recorded  : {submits}")
        if verdict_rsn:
            lines.append(f"  Reason            : {verdict_rsn}")

        return lines

    # ------------------------------------------------------------------
    # Atomic section
    # ------------------------------------------------------------------

    def _format_atomic(self, result: dict) -> List[str]:
        lines    = []
        tests    = result.get('test_results', [])
        detected = result.get('detected', False)

        lines.append(self._verdict_line(detected))

        if not tests:
            lines.append("  No test results recorded.")
            return lines

        lines.append("  ATT\u0026CK Test Results:")
        lines.append(f"  {'\u2500' * 56}")

        for t in tests:
            tid     = t.get('tid', '???????')
            tname   = t.get('name', t.get('test', 'Unknown'))
            det     = t.get('detected', False)
            detail  = t.get('detail', '')
            elapsed = t.get('elapsed', '')
            badge   = '[DETECTED]    ' if det else '[NOT DETECTED]'
            lines.append(f"    {badge}  {tid:<12}  {tname}")
            if detail:
                lines.append(f"                       Detail  : {detail}")
            if elapsed:
                lines.append(f"                       Elapsed : {elapsed}s")

        n_det = sum(1 for t in tests if t.get('detected', False))
        lines.append(f"  {'\u2500' * 56}")
        lines.append(f"  Overall: {n_det}/{len(tests)} techniques DETECTED by AV")
        return lines

    # ------------------------------------------------------------------
    # ABAE section
    # ------------------------------------------------------------------

    def _format_abae(self, result: dict) -> List[str]:
        lines   = []
        tests   = result.get('test_results', [])
        verdict = result.get('abae_verdict', 'NOT RUN')
        detected = result.get('detected', False)

        lines.append(self._verdict_line(detected))

        if not tests:
            lines.append("  No behavioral test results recorded.")
            lines.append(f"  Signature-Independent Protection: {verdict}")
            return lines

        lines.append("  Behavioral Test Results:")
        lines.append(f"  {'\u2500' * 56}")

        for t in tests:
            tid          = t.get('tid', '?????')
            tname        = t.get('name', t.get('test', 'Unknown'))
            det          = t.get('detected', False)
            detail       = t.get('detail', '')
            elapsed      = t.get('elapsed', '')
            det_lat      = t.get('detection_latency', None)
            extra        = t.get('extra', {})
            badge        = '[DETECTED]    ' if det else '[NOT DETECTED]'
            lines.append(f"    {badge}  {tid:<6}  {tname}")
            if detail:
                lines.append(f"                       Detail  : {detail[:120]}")
            if det_lat:
                lines.append(f"                       Latency : {det_lat}s")
            if elapsed:
                lines.append(f"                       Elapsed : {elapsed}s")
            # Extra per-test metrics
            if extra.get('files_modified_before_detection') is not None:
                lines.append(f"                       Files modified before block : "
                             f"{extra['files_modified_before_detection']}")
            if extra.get('avg_entropy_bits'):
                lines.append(f"                       Avg entropy : "
                             f"{extra['avg_entropy_bits']} bits/byte")
            if extra.get('processes_spawned') is not None:
                lines.append(f"                       Processes spawned : "
                             f"{extra['processes_spawned']}/{extra.get('processes_target', '?')}")
            if extra.get('registry_op_success') is not None:
                lines.append(f"                       Registry op success : "
                             f"{extra['registry_op_success']}")
            if extra.get('consistency_rate'):
                lines.append(f"                       Consistency rate : "
                             f"{extra['consistency_rate']}")

        n_det = sum(1 for t in tests if t.get('detected', False))
        lines.append(f"  {'\u2500' * 56}")
        lines.append(f"  Detected: {n_det}/{len(tests)} behavioral anomaly tests")
        lines.append(f"  Signature-Independent Protection: {verdict}")
        return lines

    # ------------------------------------------------------------------
    # Main compile
    # ------------------------------------------------------------------

    def compile_results(self, module_results: List[Dict], av_name: str) -> str:
        output = []
        output.append("=" * 62)
        output.append("  AV BENCHMARK TEST RESULTS")
        output.append("=" * 62)
        output.append(f"  Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append(f"  AV       : {av_name}")
        output.append("")
        output.append("-" * 62)
        output.append("  MODULE RESULTS")
        output.append("-" * 62)

        total_time = 0.0
        all_cpu_avg = []
        all_cpu_peak = []
        all_ram_avg = []
        all_ram_peak = []

        for result in module_results:
            module_id  = result.get('module_id', '?')
            name       = result.get('name', 'Unknown')
            exec_time  = result.get('execution_time', 0)
            status     = result.get('status', 'Unknown')
            metrics    = result.get('metrics', {})

            output.append("")
            output.append(f"  Module {module_id}: {name}")
            output.append(f"  {'─' * 56}")
            output.append(f"  Execution Time  : {exec_time}s")
            output.append(f"  Status          : {status}")

            # --- Module-specific sections ---
            if name == "EICAR Test":
                output.extend(self._format_eicar(result, metrics))

            elif name == "GoPhish Simulation":
                output.extend(self._format_gophish(result))

            elif name == "Atomic Red Team":
                output.extend(self._format_atomic(result))

            elif name == "ABAE Behavioral Engine":
                output.extend(self._format_abae(result))

            # Generic fallback for any other module with test_results
            elif 'test_results' in result:
                output.append("  Individual Test Results:")
                for test in result['test_results']:
                    status_text = "[DETECTED]" if test['detected'] else "[NOT DETECTED]"
                    output.append(f"    - {test['test']}: {status_text}")

            # --- Performance metrics ---
            output.append("")
            output.append("  System Performance During Test:")
            output.append(f"    CPU    : Avg {metrics.get('cpu_avg', 0)}%  |  Peak {metrics.get('cpu_peak', 0)}%")

            ram_avg_val  = metrics.get('ram_avg', 0)
            ram_peak_val = metrics.get('ram_peak', 0)
            output.append(f"    RAM Δ  : Avg {self._fmt_ram(ram_avg_val)}  |  Peak {self._fmt_ram(ram_peak_val)}")
            output.append(f"    Disk   : Read {metrics.get('disk_read_mb', 0)} MB  |  Write {metrics.get('disk_write_mb', 0)} MB")

            # Accumulate summary totals
            total_time += exec_time
            if metrics.get('cpu_avg'):
                all_cpu_avg.append(metrics['cpu_avg'])
            if metrics.get('cpu_peak'):
                all_cpu_peak.append(metrics['cpu_peak'])
            if metrics.get('ram_avg') is not None:
                all_ram_avg.append(metrics['ram_avg'])
            if metrics.get('ram_peak') is not None:
                all_ram_peak.append(metrics['ram_peak'])

        # --- Summary ---
        output.append("")
        output.append("=" * 62)
        output.append("  SUMMARY")
        output.append("-" * 62)
        output.append(f"  Total Execution Time : {round(total_time, 2)}s")

        if all_cpu_avg:
            output.append(f"  Avg CPU Usage        : {round(sum(all_cpu_avg) / len(all_cpu_avg), 1)}%")
        if all_cpu_peak:
            output.append(f"  Peak CPU Usage       : {round(max(all_cpu_peak), 1)}%")
        if all_ram_avg:
            avg_r = round(sum(all_ram_avg) / len(all_ram_avg), 2)
            output.append(f"  Avg RAM Δ            : {self._fmt_ram(avg_r)}")
        if all_ram_peak:
            peak_r = round(max(all_ram_peak), 2)
            output.append(f"  Peak RAM Δ           : {self._fmt_ram(peak_r)}")

        output.append("=" * 62)

        # === PHYSICAL SCORE ===
        scores = calculate_scores(module_results)
        bd     = scores.get('breakdown', {})
        output.append("")
        output.append("=" * 62)
        output.append("  PHYSICAL SCORE  (Detection 50% + Performance 30%)")
        output.append("-" * 62)
        output.append(f"  Detection Score   : {scores['detection_score']:>5.2f} / 5.00")
        output.append(f"    Modules detected   : {bd.get('detected_count',0)}/{bd.get('total_modules',0)}"
                      f"  (+{bd.get('rate_score',0):.2f} pts)")
        best_lat = bd.get('best_latency_s')
        if best_lat is not None:
            output.append(f"    Best latency       : {best_lat:.2f}s  (+{bd.get('speed_score',0):.2f} pts)")
        else:
            output.append(f"    Best latency       : N/A  (+0.00 pts — no detection recorded)")
        output.append(f"  Performance Score : {scores['performance_score']:>5.2f} / 3.00")
        output.append(f"    CPU avg            : {bd.get('agg_cpu_avg',0):.1f}%")
        output.append(f"    RAM peak           : {bd.get('agg_ram_peak_mb',0):.1f} MB")
        output.append(f"    Disk write         : {bd.get('agg_disk_write_mb',0):.1f} MB")
        output.append(f"  {'─' * 38}")
        output.append(f"  Physical Total    : {scores['physical_total']:>5.2f} / 8.00")
        output.append(f"  (Usability 2.00 pts scored separately by comparison website)")
        output.append("=" * 62)

        return "\n".join(output)

    # ------------------------------------------------------------------

    def export_to_txt(self, results_text: str) -> str:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename  = f"benchmark_results_{timestamp}.txt"
        filepath  = os.path.join(self.results_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(results_text)

        return filepath

    # ------------------------------------------------------------------
    # Upload & Payload
    # ------------------------------------------------------------------

    def build_upload_payload(self, module_results: List[Dict], av_name: str) -> dict:
        """Assemble the JSON payload dict for the server upload."""
        scores = calculate_scores(module_results)
        bd     = scores.get('breakdown', {})

        # Per-module detected booleans (by canonical name)
        def _mod_detected(name_fragment):
            for r in module_results:
                if name_fragment.lower() in r.get('name', '').lower():
                    return 1 if r.get('detected', False) else 0
            return 0

        def _abae_verdict():
            for r in module_results:
                if 'abae' in r.get('name', '').lower():
                    return r.get('abae_verdict', 'NOT RUN')
            return 'NOT RUN'

        payload = {
            "av_name":                   av_name,
            "run_id":                    f"run_{str(uuid.uuid4())[:8]}",
            "detection_score":           scores['detection_score'],
            "performance_score":         scores['performance_score'],
            "physical_total":            scores['physical_total'],
            "eicar_detected":            _mod_detected('eicar'),
            "gophish_detected":          _mod_detected('gophish'),
            "atomic_detected":           _mod_detected('atomic'),
            "abae_detected":             _mod_detected('abae'),
            "abae_verdict":              _abae_verdict(),
            "best_detection_latency_s":  bd.get('best_latency_s'),
            "cpu_avg":                   bd.get('agg_cpu_avg', 0),
            "ram_peak_mb":               bd.get('agg_ram_peak_mb', 0),
            "disk_write_mb":             bd.get('agg_disk_write_mb', 0),
            "raw_json":                  json.dumps(module_results),
        }
        return payload

    def upload_to_server(self, module_results: List[Dict], av_name: str,
                         server_url: str) -> tuple:
        """
        Build payload, POST to server, return (success: bool, message: str).
        message contains the run_id on success or error detail on failure.
        """
        payload = self.build_upload_payload(module_results, av_name)
        run_id  = payload['run_id']

        print(f"[Upload] Physical Score: {payload['physical_total']:.2f}/8.00")
        print(f"[Upload] Uploading run '{run_id}' to {server_url} ...")

        try:
            json_bytes = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                server_url,
                data=json_bytes,
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read().decode('utf-8')

            try:
                resp_json = json.loads(body)
                if resp_json.get('status') == 'ok':
                    msg = (f"Saved  run_id={resp_json.get('run_id', run_id)}  "
                           f"id={resp_json.get('id', '?')}  "
                           f"at {resp_json.get('timestamp', '?')}")
                    print(f"[Upload] Server OK — {msg}")
                    return True, msg
                else:
                    err = resp_json.get('message', body)
                    print(f"[Upload] Server returned error: {err}")
                    return False, f"Server error: {err}"
            except json.JSONDecodeError:
                # Non-JSON response (old PHP echo)
                print(f"[Upload] Server raw response: {body}")
                return True, body

        except urllib.error.URLError as e:
            msg = f"Network error — is the server reachable? ({e.reason})"
            print(f"[Upload] FAILED: {msg}")
            return False, msg
        except Exception as e:
            msg = f"Unexpected error: {e}"
            print(f"[Upload] FAILED: {msg}")
            return False, msg
