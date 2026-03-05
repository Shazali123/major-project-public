<?php
/**
 * upload_results.php — AV Benchmark Results Receiver
 * ====================================================
 * Deploy to: /var/www/html/upload_results.php
 *
 * Accepts a JSON POST from the Python benchmark tool,
 * creates/opens the SQLite database, inserts the results,
 * and returns a JSON response with the run ID and timestamp.
 *
 * Expected JSON payload fields:
 *   av_name, run_id, detection_score, performance_score,
 *   physical_total, eicar_detected, gophish_detected,
 *   atomic_detected, abae_detected, abae_verdict,
 *   best_detection_latency_s, cpu_avg, ram_peak_mb,
 *   disk_write_mb, raw_json
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');                 // Allow comparison website to fetch
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight (CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Only accept POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method not allowed']);
    exit;
}

// Parse incoming JSON
$raw  = file_get_contents('php://input');
$data = json_decode($raw, true);

if (!$data || !isset($data['av_name'], $data['run_id'])) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid or missing JSON payload']);
    exit;
}

// Connect to (or create) the SQLite database
$db_path = '/var/www/html/av_benchmarks.sqlite';

try {
    $db = new SQLite3($db_path);
    $db->enableExceptions(true);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Cannot open database: ' . $e->getMessage()]);
    exit;
}

// Create table if first run
$db->exec("CREATE TABLE IF NOT EXISTS benchmark_results (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                   TEXT    UNIQUE,
    av_name                  TEXT    NOT NULL,
    timestamp                DATETIME DEFAULT CURRENT_TIMESTAMP,
    detection_score          REAL    DEFAULT 0,
    performance_score        REAL    DEFAULT 0,
    physical_total           REAL    DEFAULT 0,
    eicar_detected           INTEGER DEFAULT 0,
    gophish_detected         INTEGER DEFAULT 0,
    atomic_detected          INTEGER DEFAULT 0,
    abae_detected            INTEGER DEFAULT 0,
    abae_verdict             TEXT    DEFAULT 'NOT RUN',
    best_detection_latency_s REAL    DEFAULT NULL,
    cpu_avg                  REAL    DEFAULT 0,
    ram_peak_mb              REAL    DEFAULT 0,
    disk_write_mb            REAL    DEFAULT 0,
    raw_json                 TEXT
)");

// Helper: safe float from payload
function _f($data, $key, $default = 0.0) {
    return isset($data[$key]) ? (float)$data[$key] : $default;
}
function _i($data, $key, $default = 0) {
    return isset($data[$key]) ? (int)$data[$key] : $default;
}
function _s($data, $key, $default = '') {
    return isset($data[$key]) ? (string)$data[$key] : $default;
}

// Prepare and execute INSERT
try {
    $stmt = $db->prepare("
        INSERT OR REPLACE INTO benchmark_results
            (run_id, av_name, detection_score, performance_score, physical_total,
             eicar_detected, gophish_detected, atomic_detected, abae_detected, abae_verdict,
             best_detection_latency_s, cpu_avg, ram_peak_mb, disk_write_mb, raw_json)
        VALUES
            (:run_id, :av_name, :det_score, :perf_score, :phys_total,
             :eicar, :gophish, :atomic, :abae, :abae_v,
             :best_lat, :cpu_avg, :ram_peak, :disk_write, :raw_json)
    ");

    $stmt->bindValue(':run_id',     _s($data, 'run_id'));
    $stmt->bindValue(':av_name',    _s($data, 'av_name'));
    $stmt->bindValue(':det_score',  _f($data, 'detection_score'));
    $stmt->bindValue(':perf_score', _f($data, 'performance_score'));
    $stmt->bindValue(':phys_total', _f($data, 'physical_total'));
    $stmt->bindValue(':eicar',      _i($data, 'eicar_detected'));
    $stmt->bindValue(':gophish',    _i($data, 'gophish_detected'));
    $stmt->bindValue(':atomic',     _i($data, 'atomic_detected'));
    $stmt->bindValue(':abae',       _i($data, 'abae_detected'));
    $stmt->bindValue(':abae_v',     _s($data, 'abae_verdict', 'NOT RUN'));
    $stmt->bindValue(':best_lat',   isset($data['best_detection_latency_s']) ? (float)$data['best_detection_latency_s'] : null, SQLITE3_FLOAT);
    $stmt->bindValue(':cpu_avg',    _f($data, 'cpu_avg'));
    $stmt->bindValue(':ram_peak',   _f($data, 'ram_peak_mb'));
    $stmt->bindValue(':disk_write', _f($data, 'disk_write_mb'));
    $stmt->bindValue(':raw_json',   _s($data, 'raw_json', $raw));  // store original if not pre-encoded

    $stmt->execute();

    $inserted_id = $db->lastInsertRowID();
    $timestamp   = date('Y-m-d H:i:s');

    echo json_encode([
        'status'    => 'ok',
        'id'        => $inserted_id,
        'run_id'    => _s($data, 'run_id'),
        'timestamp' => $timestamp,
        'message'   => 'Results saved successfully',
    ]);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Insert failed: ' . $e->getMessage()]);
}

$db->close();
?>
