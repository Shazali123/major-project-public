"""
AV Benchmark Dashboard — Flask API
===================================
Serves benchmark results from the SQLite database as JSON.

Endpoints:
  GET /api/results          - All runs (supports ?sort=col&order=asc|desc)
  GET /api/results/<run_id> - Single run with full raw_json detail
  GET /api/summary          - Aggregated stats per AV name
  GET /api/avs              - List of distinct AV names

Deploy to: /var/www/html/api.py
Run via systemd: see av_benchmark_dashboard.service
"""

import sqlite3
import json
from flask import Flask, jsonify, request, abort
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests from the frontend

DB_PATH = "/var/www/html/av_benchmarks.sqlite"

SORTABLE_COLUMNS = {
    "id", "run_id", "av_name", "timestamp",
    "detection_score", "performance_score", "physical_total",
    "eicar_detected", "gophish_detected", "atomic_detected", "abae_detected",
    "abae_verdict", "best_detection_latency_s",
    "cpu_avg", "ram_peak_mb", "disk_write_mb",
}


def get_db():
    """Open a read-only connection to the SQLite database."""
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.OperationalError:
        # DB doesn't exist yet — return None, endpoints handle gracefully
        return None


def row_to_dict(row):
    d = dict(row)
    # Parse raw_json if present so the frontend can use it directly
    if "raw_json" in d and d["raw_json"]:
        try:
            d["raw_json"] = json.loads(d["raw_json"])
        except (json.JSONDecodeError, TypeError):
            pass
    return d


# ---------------------------------------------------------------------------
# GET /api/results
# ---------------------------------------------------------------------------
@app.route("/api/results", methods=["GET"])
def get_results():
    sort_col = request.args.get("sort", "physical_total")
    order    = request.args.get("order", "desc").upper()
    limit    = request.args.get("limit", 200, type=int)
    av_filter = request.args.get("av", None)

    # Whitelist sort column and order to prevent SQL injection
    if sort_col not in SORTABLE_COLUMNS:
        sort_col = "physical_total"
    if order not in ("ASC", "DESC"):
        order = "DESC"

    conn = get_db()
    if conn is None:
        return jsonify({"error": "Database not found", "results": []}), 200

    try:
        query = f"""
            SELECT id, run_id, av_name, timestamp,
                   detection_score, performance_score, physical_total,
                   eicar_detected, gophish_detected, atomic_detected, abae_detected,
                   abae_verdict, best_detection_latency_s,
                   cpu_avg, ram_peak_mb, disk_write_mb
            FROM benchmark_results
            {"WHERE av_name = ?" if av_filter else ""}
            ORDER BY {sort_col} {order}
            LIMIT ?
        """
        params = ([av_filter, limit] if av_filter else [limit])
        rows = conn.execute(query, params).fetchall()
        return jsonify({"results": [row_to_dict(r) for r in rows]})
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /api/results/<run_id>
# ---------------------------------------------------------------------------
@app.route("/api/results/<run_id>", methods=["GET"])
def get_single_result(run_id):
    conn = get_db()
    if conn is None:
        abort(404)
    try:
        row = conn.execute(
            "SELECT * FROM benchmark_results WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            abort(404)
        return jsonify(row_to_dict(row))
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /api/summary
# ---------------------------------------------------------------------------
@app.route("/api/summary", methods=["GET"])
def get_summary():
    conn = get_db()
    if conn is None:
        return jsonify({"summary": []}), 200
    try:
        rows = conn.execute("""
            SELECT
                av_name,
                COUNT(*)                        AS run_count,
                ROUND(MAX(physical_total), 2)   AS best_score,
                ROUND(AVG(physical_total), 2)   AS avg_score,
                ROUND(MAX(detection_score), 2)  AS best_detection,
                ROUND(AVG(cpu_avg), 1)          AS avg_cpu,
                ROUND(AVG(ram_peak_mb), 1)      AS avg_ram_mb,
                MAX(timestamp)                  AS last_run
            FROM benchmark_results
            GROUP BY av_name
            ORDER BY best_score DESC
        """).fetchall()
        return jsonify({"summary": [dict(r) for r in rows]})
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /api/avs
# ---------------------------------------------------------------------------
@app.route("/api/avs", methods=["GET"])
def get_avs():
    conn = get_db()
    if conn is None:
        return jsonify({"avs": []}), 200
    try:
        rows = conn.execute(
            "SELECT DISTINCT av_name FROM benchmark_results ORDER BY av_name"
        ).fetchall()
        return jsonify({"avs": [r["av_name"] for r in rows]})
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def health():
    conn = get_db()
    if conn is None:
        return jsonify({"status": "db_missing"}), 503
    conn.close()
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # Run on all interfaces so Nginx can reach it
    app.run(host="0.0.0.0", port=5000, debug=False)
