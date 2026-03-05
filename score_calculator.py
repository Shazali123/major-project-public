"""
Score Calculator — Weighted 8-Point Physical Score
===================================================
Scoring breakdown (out of 8 pts total):

    Detection Score   — 5 pts max  (50% of total 10-pt model)
    Performance Score — 3 pts max  (30% of total 10-pt model)
    Usability Score   — 2 pts max  (20%) → added separately by comparison website

Detection sub-score
-------------------
  Module detection rate  : (detected_count / total_modules) × 3.0
  Detection latency      : max(0.0, 2.0 − best_latency_s × 0.15)

Performance sub-score
---------------------
  Start at 3.0, deduct:
    cpu_avg      × 0.015
    ram_peak_mb  × 0.005
    disk_write_mb× 0.002
  Clamped to [0.0, 3.0]
"""


def calculate_scores(module_results: list) -> dict:
    """
    Compute the Physical Score from a list of module result dicts.

    Parameters
    ----------
    module_results : list of dicts (each is a module's get_results() output)

    Returns
    -------
    dict with keys:
        detection_score   float  0.0–5.0
        performance_score float  0.0–3.0
        physical_total    float  0.0–8.0
        breakdown         dict   raw inputs used for transparency
    """
    if not module_results:
        return _zero_scores()

    # ------------------------------------------------------------------ #
    # 1. Gather detection info across all modules                         #
    # ------------------------------------------------------------------ #
    total_modules  = len(module_results)
    detected_count = 0
    latencies      = []          # detection_time values in seconds

    for r in module_results:
        if r.get("detected", False):
            detected_count += 1

        metrics = r.get("metrics", {})
        dt = metrics.get("detection_time")
        if dt and dt > 0:
            latencies.append(dt)

    best_latency_s = min(latencies) if latencies else None

    # ------------------------------------------------------------------ #
    # 2. Detection Score (5 pts max)                                      #
    # ------------------------------------------------------------------ #
    # Part A — module detection rate (0–3 pts)
    rate_score = (detected_count / total_modules) * 3.0

    # Part B — detection speed (0–2 pts)
    if best_latency_s is not None:
        speed_score = max(0.0, 2.0 - best_latency_s * 0.15)
    else:
        speed_score = 0.0   # no detection recorded → no speed bonus

    detection_score = round(rate_score + speed_score, 2)

    # ------------------------------------------------------------------ #
    # 3. Performance Score (3 pts max)                                    #
    # ------------------------------------------------------------------ #
    # Aggregate weighted-average CPU, peak RAM, total disk write
    cpu_avgs      = []
    ram_peaks     = []
    disk_writes   = []

    for r in module_results:
        m = r.get("metrics", {})
        if m.get("cpu_avg") is not None:
            cpu_avgs.append(m["cpu_avg"])
        if m.get("ram_peak") is not None:
            ram_peaks.append(m["ram_peak"])
        if m.get("disk_write_mb") is not None:
            disk_writes.append(m["disk_write_mb"])

    agg_cpu_avg      = round(sum(cpu_avgs) / len(cpu_avgs), 2)      if cpu_avgs      else 0.0
    agg_ram_peak_mb  = round(max(ram_peaks), 2)                      if ram_peaks     else 0.0
    agg_disk_write   = round(sum(disk_writes), 2)                    if disk_writes   else 0.0

    perf_score = 3.0
    perf_score -= agg_cpu_avg     * 0.015
    perf_score -= agg_ram_peak_mb * 0.005
    perf_score -= agg_disk_write  * 0.002
    performance_score = round(max(0.0, min(3.0, perf_score)), 2)

    # ------------------------------------------------------------------ #
    # 4. Physical Total                                                   #
    # ------------------------------------------------------------------ #
    physical_total = round(detection_score + performance_score, 2)

    return {
        "detection_score":   detection_score,
        "performance_score": performance_score,
        "physical_total":    physical_total,
        "breakdown": {
            "total_modules":         total_modules,
            "detected_count":        detected_count,
            "best_latency_s":        best_latency_s,
            "rate_score":            round(rate_score, 2),
            "speed_score":           round(speed_score, 2),
            "agg_cpu_avg":           agg_cpu_avg,
            "agg_ram_peak_mb":       agg_ram_peak_mb,
            "agg_disk_write_mb":     agg_disk_write,
        },
    }


def _zero_scores() -> dict:
    return {
        "detection_score":   0.0,
        "performance_score": 0.0,
        "physical_total":    0.0,
        "breakdown": {
            "total_modules":     0,
            "detected_count":    0,
            "best_latency_s":    None,
            "rate_score":        0.0,
            "speed_score":       0.0,
            "agg_cpu_avg":       0.0,
            "agg_ram_peak_mb":   0.0,
            "agg_disk_write_mb": 0.0,
        },
    }
