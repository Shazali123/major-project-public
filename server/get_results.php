<?php
/**
 * get_results.php — AV Benchmark Results API
 * ============================================
 * Deploy to: /var/www/html/get_results.php
 *
 * Called by the comparison website to fetch benchmark data.
 * Returns JSON. Supports optional query parameters:
 *
 *   ?av_name=Defender      → filter by AV name
 *   ?limit=10              → max rows (default 50)
 *   ?order=asc|desc        → sort by timestamp (default desc)
 *   ?run_id=run_abc123     → fetch a single run
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$db_path = '/var/www/html/av_benchmarks.sqlite';

if (!file_exists($db_path)) {
    http_response_code(404);
    echo json_encode(['status' => 'error', 'message' => 'No benchmark data yet. Run the benchmark tool first.']);
    exit;
}

try {
    $db = new SQLite3($db_path, SQLITE3_OPEN_READONLY);
    $db->enableExceptions(true);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Cannot open database: ' . $e->getMessage()]);
    exit;
}

// --- Query parameters ---
$av_filter = isset($_GET['av_name']) ? trim($_GET['av_name']) : null;
$run_id    = isset($_GET['run_id'])  ? trim($_GET['run_id'])  : null;
$limit     = isset($_GET['limit'])  ? max(1, min(200, (int)$_GET['limit'])) : 50;
$order     = (isset($_GET['order']) && strtolower($_GET['order']) === 'asc') ? 'ASC' : 'DESC';

// Build query — exclude raw_json from list view to keep response small
$select_cols = "id, run_id, av_name, timestamp,
                detection_score, performance_score, physical_total,
                eicar_detected, gophish_detected, atomic_detected, abae_detected, abae_verdict,
                best_detection_latency_s, cpu_avg, ram_peak_mb, disk_write_mb";

if ($run_id) {
    // Single-run fetch — include full raw_json
    $stmt = $db->prepare("SELECT $select_cols, raw_json
                          FROM benchmark_results
                          WHERE run_id = :run_id
                          LIMIT 1");
    $stmt->bindValue(':run_id', $run_id);
} elseif ($av_filter) {
    $stmt = $db->prepare("SELECT $select_cols
                          FROM benchmark_results
                          WHERE av_name LIKE :av
                          ORDER BY timestamp $order
                          LIMIT :lmt");
    $stmt->bindValue(':av',  '%' . $av_filter . '%');
    $stmt->bindValue(':lmt', $limit, SQLITE3_INTEGER);
} else {
    $stmt = $db->prepare("SELECT $select_cols
                          FROM benchmark_results
                          ORDER BY timestamp $order
                          LIMIT :lmt");
    $stmt->bindValue(':lmt', $limit, SQLITE3_INTEGER);
}

$result = $stmt->execute();
$rows   = [];

while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    // Decode raw_json if present (single-run fetch)
    if (isset($row['raw_json']) && $row['raw_json']) {
        $row['raw_json'] = json_decode($row['raw_json'], true);
    }
    // Cast numerics properly
    foreach (['detection_score','performance_score','physical_total',
              'best_detection_latency_s','cpu_avg','ram_peak_mb','disk_write_mb'] as $col) {
        if (isset($row[$col])) $row[$col] = (float)$row[$col];
    }
    foreach (['id','eicar_detected','gophish_detected','atomic_detected','abae_detected'] as $col) {
        if (isset($row[$col])) $row[$col] = (int)$row[$col];
    }
    $rows[] = $row;
}

$db->close();

echo json_encode([
    'status' => 'ok',
    'count'  => count($rows),
    'data'   => $rows,
]);
?>
