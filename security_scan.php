<?php
// OpenCart All-in-One Security Auditor - v4.0
// REFINED: VirusTotal link now only appears for dangerous files or for manual upload on 'not found'.

@ini_set('memory_limit', '512M');

// --- Main Configuration ---
define('DEBUG_MODE', true); // Set to false in production
define('MAX_FILE_SIZE', 50 * 1024 * 1024);
define('SCAN_TIMEOUT', 600);

// --- Malicious Code Scanner Configuration ---
define('SCAN_MALWARE', true);
$suspicious_patterns = [
    'SQL-инъекция' => '/\bquery\s*\(\s*["\'].*\.\s*\$_(GET|POST|REQUEST|COOKIE)\b/i',
    'Подозрительный CONCAT' => '/\b(mysql|mysqli)_query\s*\(\s*["\'].*concat\s*\(.*\)/i',
    'base64_decode' => '/\bbase64_decode\s*\(/i',
    'eval' => '/\beval\s*\(/i',
    'gzinflate' => '/\bgzinflate\s*\(/i',
    'shell_exec' => '/\bshell_exec\s*\(/i',
    'system' => '/\bsystem\s*\(/i',
    'passthru' => '/\bpassthru\s*\(/i',
    'Remote Code Execution' => '/`.*`.*=.*\$_(GET|POST|REQUEST|COOKIE)/i',
    'File Write from Request' => '/\bfile_put_contents\s*\(.*\$_(GET|POST|REQUEST|COOKIE)/i'
];
$malware_scan_extensions = ['php', 'tpl', 'twig'];

// --- Basic Setup ---
if (DEBUG_MODE) {
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
} else {
    ini_set('display_errors', 0);
}
set_time_limit(SCAN_TIMEOUT);
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Simple Diff implementation
class SimpleDiff {
    public static function compare($old, $new) {
        $from_lines = explode("\n", $old);
        $to_lines = explode("\n", $new);
        $diff = new \SplQueue();
        $matrix = [];
        $max_from = count($from_lines);
        $max_to = count($to_lines);

        for ($i = 0; $i <= $max_from; $i++) {
            for ($j = 0; $j <= $max_to; $j++) {
                $matrix[$i][$j] = 0;
            }
        }

        for ($i = 1; $i <= $max_from; $i++) {
            for ($j = 1; $j <= $max_to; $j++) {
                if (isset($from_lines[$i - 1]) && isset($to_lines[$j - 1]) && trim($from_lines[$i - 1]) == trim($to_lines[$j - 1])) {
                    $matrix[$i][$j] = $matrix[$i - 1][$j - 1] + 1;
                } else {
                    $matrix[$i][$j] = max($matrix[$i - 1][$j], $matrix[$i][$j - 1]);
                }
            }
        }

        $i = $max_from;
        $j = $max_to;

        while ($i > 0 || $j > 0) {
            if ($i > 0 && $j > 0 && isset($from_lines[$i - 1]) && isset($to_lines[$j - 1]) && trim($from_lines[$i - 1]) == trim($to_lines[$j - 1])) {
                $diff->enqueue(['type' => 'unmodified', 'line' => $from_lines[$i - 1]]);
                $i--; $j--;
            } elseif ($j > 0 && ($i == 0 || $matrix[$i][$j - 1] >= $matrix[$i - 1][$j])) {
                $diff->enqueue(['type' => 'added', 'line' => $to_lines[$j - 1]]);
                $j--;
            } elseif ($i > 0 && ($j == 0 || $matrix[$i][$j - 1] < $matrix[$i - 1][$j])) {
                $diff->enqueue(['type' => 'deleted', 'line' => $from_lines[$i - 1]]);
                $i--;
            } else {
                $i--; $j--;
            }
        }

        $html = '<pre><code>';
        while (!$diff->isEmpty()) {
            $change = $diff->dequeue();
            $line = htmlspecialchars($change['line']);
            if ($change['type'] == 'added') {
                $html .= '<span class="diff-added">+ ' . $line . '</span>' . "\n";
            } elseif ($change['type'] == 'deleted') {
                $html .= '<span class="diff-deleted">- ' . $line . '</span>' . "\n";
            }
        }
        $html .= '</code></pre>';
        return $html;
    }
}


class OpenCartAuditor {
    public $scan_dir;
    private $log_file;
    private $results = ['integrity' => [], 'date' => [], 'malware' => []];
    private $stats = ['integrity' => ['total' => 0, 'ok' => 0, 'modified' => 0, 'missing' => 0], 'date' => 0, 'malware' => 0];
    private $excluded_dirs = ['system/storage/', 'image/', 'catalog/view/theme/', 'install/'];
    private $excluded_files = ['config.php', 'admin/config.php', '.htaccess', 'php.ini', 'robots.txt'];
    private $storage_path;

    public function __construct() {
        if (file_exists(__DIR__ . '/config.php')) {
            ob_start(); require(__DIR__ . '/config.php'); ob_end_clean();
            $this->storage_path = defined('DIR_STORAGE') ? DIR_STORAGE : __DIR__ . '/system/storage/';
        } else {
            $this->storage_path = __DIR__ . '/system/storage/';
        }
        $this->storage_path = rtrim($this->storage_path, '/') . '/';
        
        if (!is_dir($this->storage_path) || !is_writable($this->storage_path)) {
            throw new Exception("Директория 'storage' не найдена или недоступна: " . htmlspecialchars($this->storage_path));
        }

        $this->scan_dir = $this->storage_path . 'cache/auditor_tmp_' . uniqid();
        $this->log_file = $this->storage_path . 'logs/auditor.log';
        if (DEBUG_MODE && !is_dir(dirname($this->log_file))) {
            @mkdir(dirname($this->log_file), 0755, true);
        }
    }
    
    public function cleanup() {
        if (!empty($this->scan_dir) && is_dir($this->scan_dir)) $this->rrmdir($this->scan_dir);
    }

    private function log($msg) { if (DEBUG_MODE) @error_log(date('[Y-m-d H:i:s] ') . $msg . PHP_EOL, 3, $this->log_file); }

    public function runScans($zip_file, $date_from) {
        if ($zip_file && $zip_file['error'] === UPLOAD_ERR_OK) {
            $this->scanIntegrity($zip_file);
        }
        $this->scanLiveFiles($date_from);
        return ['success' => true, 'results' => $this->results, 'stats' => $this->stats];
    }
    
    private function scanIntegrity($zip_file) {
        $this->log("Starting integrity scan...");
        if (!@mkdir($this->scan_dir, 0755, true)) throw new Exception("Не удалось создать временную директорию.");
        $zip_path = $this->scan_dir . '/upload.zip';
        if (!move_uploaded_file($zip_file['tmp_name'], $zip_path)) throw new Exception("Не удалось сохранить загруженный файл.");

        $zip = new ZipArchive();
        if ($zip->open($zip_path) !== TRUE) throw new Exception("Ошибка открытия ZIP-архива.");
        $extract_path = $this->scan_dir . '/original';
        $zip->extractTo($extract_path);
        $zip->close();
        @unlink($zip_path);

        $original_base = $this->findOpenCartRoot($extract_path);
        if (!$original_base) {
            $this->log("CRITICAL: Could not find OpenCart root in the extracted ZIP at {$extract_path}.");
            $debug_listing = "Структура распакованного архива:\n\n";
            $top_level_contents = @scandir($extract_path);
            if ($top_level_contents) {
                foreach ($top_level_contents as $item) {
                    if ($item === '.' || $item === '..') continue;
                    $debug_listing .= $item . (is_dir($extract_path . '/' . $item) ? '/' : '') . "\n";
                }
            } else {
                $debug_listing .= "Не удалось прочитать содержимое папки {$extract_path}.";
            }
            throw new Exception("Не найдена корневая директория OpenCart в архиве. Сравнение невозможно.<br><br><strong>Для отладки:</strong> Пожалуйста, убедитесь, что одна из этих папок (или папка внутри них) содержит файлы сайта (index.php, admin, system):<br><pre style='background-color:#f0f0f0; padding:10px; border:1px solid #ccc; white-space:pre-wrap;'>" . htmlspecialchars($debug_listing) . "</pre>");
        }

        $this->log("Found OpenCart root in ZIP at: {$original_base}");
        
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($original_base, RecursiveDirectoryIterator::SKIP_DOTS));
        foreach ($it as $file) {
            if ($file->isDir()) continue;
            $rel_path = str_replace([$original_base . '/', '\\'], ['', '/'], $file->getPathname());
            if ($this->isExcluded($rel_path)) continue;

            $this->stats['integrity']['total']++;
            $live_file = __DIR__ . '/' . $rel_path;
            
            if (!file_exists($live_file)) {
                $this->results['integrity'][] = ['file' => $rel_path, 'status' => 'Отсутствует', 'type' => 'missing'];
                $this->stats['integrity']['missing']++;
            } else {
                $hash_live = hash_file('sha256', $live_file);
                $hash_original = hash_file('sha256', $file->getPathname());
                if ($hash_live === $hash_original) {
                    $this->stats['integrity']['ok']++;
                } else {
                    $this->results['integrity'][] = ['file' => $rel_path, 'status' => 'Изменён', 'type' => 'modified'];
                    $this->stats['integrity']['modified']++;
                }
            }
        }
    }
    
    private function scanLiveFiles($date_from) {
        $this->log("Starting live file scan (date/malware)...");
        $date_threshold = $date_from ? strtotime($date_from) : null;
        global $suspicious_patterns, $malware_scan_extensions;

        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__, RecursiveDirectoryIterator::SKIP_DOTS));
        foreach ($it as $file) {
            if ($file->isDir()) continue;
            $file_path = $file->getPathname();
            $rel_path = str_replace([__DIR__ . '/', '\\'], ['', '/'], $file_path);
            if ($this->isExcluded($rel_path)) continue;

            if ($date_threshold && $file->getMTime() > $date_threshold) {
                $this->results['date'][] = ['file' => $rel_path, 'date' => date('Y-m-d H:i:s', $file->getMTime())];
                $this->stats['date']++;
            }
            
            if (SCAN_MALWARE && in_array($file->getExtension(), $malware_scan_extensions)) {
                $content = @file_get_contents($file_path);
                if ($content === false) continue;
                foreach ($suspicious_patterns as $name => $pattern) {
                    if (preg_match($pattern, $content)) {
                        $this->results['malware'][] = ['file' => $rel_path, 'pattern' => $name, 'code' => $pattern];
                        $this->stats['malware']++;
                        break;
                    }
                }
            }
        }
    }
    
    public function checkFileOnVirusTotal($file_path, $api_key) {
        if (empty($api_key)) {
            return ['error' => 'API ключ для VirusTotal не указан.'];
        }

        $real_path = realpath(__DIR__ . '/' . $file_path);
        if (!$real_path || strpos($real_path, __DIR__) !== 0) {
            return ['error' => 'Недопустимый путь к файлу.'];
        }
        if (!file_exists($real_path)) {
            return ['error' => 'Файл не найден на сервере.'];
        }

        $file_hash = hash_file('sha256', $real_path);
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://www.virustotal.com/api/v3/files/' . $file_hash);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['x-apikey: ' . $api_key]);
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $result = [
            'hash' => $file_hash,
            'positives' => 0,
            'total' => 0,
            'status_text' => 'Неизвестно',
            'status_class' => 'vt-unknown'
        ];

        if ($http_code == 200) {
            $data = json_decode($response, true);
            $stats = $data['data']['attributes']['last_analysis_stats'] ?? [];
            $positives = ($stats['malicious'] ?? 0) + ($stats['suspicious'] ?? 0);
            $total = array_sum($stats);
            
            $result['positives'] = $positives;
            $result['total'] = $total;
            if ($positives > 0) {
                $result['status_text'] = 'Обнаружены угрозы!';
                $result['status_class'] = 'vt-danger';
            } else {
                $result['status_text'] = 'Чистый';
                $result['status_class'] = 'vt-ok';
            }
        } elseif ($http_code == 404) {
            $result['status_text'] = 'Не найден в VT. <a href="https://www.virustotal.com/gui/home/upload" target="_blank">Загрузить вручную.</a>';
            $result['status_class'] = 'vt-not-found';
        } else {
            $result['status_text'] = 'Ошибка API (код: ' . $http_code . ')';
        }
        
        return $result;
    }

    private function isExcluded($path) {
        foreach ($this->excluded_files as $file) { if ($path === $file) return true; }
        foreach ($this->excluded_dirs as $dir) { if (strpos($path, $dir) === 0) return true; }
        return false;
    }
    
    public function getDiff($file_path) {
        if (!$this->scan_dir || !is_dir($this->scan_dir)) {
            return "Не удалось найти оригинальные файлы. Возможно, сессия истекла. Пожалуйста, запустите сканирование заново.";
        }
        $original_base = $this->findOpenCartRoot($this->scan_dir . '/original');
        if (!$original_base) {
            return "Не найден оригинальный файл для сравнения. Структура архива может быть некорректной.";
        }
        $original_file = $original_base . '/' . $file_path;
        $live_file = __DIR__ . '/' . $file_path;
        if (!file_exists($live_file) || !file_exists($original_file)) {
            return "Не удалось найти один из файлов для сравнения.";
        }
        $content_live = file_get_contents($live_file);
        $content_original = file_get_contents($original_file);
        return SimpleDiff::compare($content_original, $content_live);
    }
    
    private function findOpenCartRoot($path) {
        $this->log("Searching for OpenCart root inside: {$path}");
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_PATHNAME), RecursiveIteratorIterator::SELF_FIRST);
        $it->setMaxDepth(5);
        foreach ($it as $pathname) {
            if (is_dir($pathname) && basename($pathname) === 'upload') {
                if (is_file($pathname . '/index.php') && is_dir($pathname . '/admin')) {
                    $this->log("SUCCESS (Stage 1): Found 'upload' directory at: {$pathname}");
                    return $pathname;
                }
            }
        }
        $it->rewind();
        foreach ($it as $pathname) {
            if (is_dir($pathname)) {
                if (is_file($pathname . '/index.php') && is_dir($pathname . '/admin') && is_dir($pathname . '/system')) {
                    $this->log("SUCCESS (Stage 2): Found a valid OpenCart root at: {$pathname}");
                    return $pathname;
                }
            }
        }
        if (is_file($path . '/index.php') && is_dir($path . '/admin') && is_dir($path . '/system')) {
            $this->log("SUCCESS (Stage 3): The extraction root itself is the OpenCart root: {$path}");
            return $path;
        }
        $this->log("FAILURE: Could not find a valid OpenCart root directory in the archive.");
        return false;
    }
    
    private function rrmdir($dir) {
        if (!is_dir($dir)) return;
        $objects = scandir($dir);
        foreach ($objects as $object) {
            if ($object != "." && $object != "..") {
                if (is_dir($dir . "/" . $object))
                    $this->rrmdir($dir . "/" . $object);
                else
                    unlink($dir . "/" . $object);
            }
        }
        rmdir($dir);
    }
}

// --- Main Logic & Shutdown Function ---
$auditor_result = null;
$error_message = '';
$auditor = null;

register_shutdown_function(function () {
    $auditor = isset($GLOBALS['auditor']) ? $GLOBALS['auditor'] : null;
    if ($auditor && method_exists($auditor, 'cleanup')) {
        // Cleanup logic here if needed.
    }
});

try {
    session_write_close();
    session_start();
    
    if (isset($_POST['action']) && $_POST['action'] == 'check_virustotal') {
        if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
             header('Content-Type: application/json');
             echo json_encode(['error' => 'Ошибка CSRF-токена.']);
             exit();
        }
        $auditor = new OpenCartAuditor();
        $file_to_check = $_POST['file'] ?? '';
        $api_key = $_POST['api_key'] ?? '';
        $vt_result = $auditor->checkFileOnVirusTotal($file_to_check, $api_key);
        header('Content-Type: application/json');
        echo json_encode($vt_result);
        exit();
    }

    if (isset($_POST['action']) && $_POST['action'] == 'get_diff') {
        if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
             die("Ошибка CSRF-токена.");
        }
        if (isset($_SESSION['auditor_scan_dir']) && is_dir($_SESSION['auditor_scan_dir'])) {
             $auditor = new OpenCartAuditor();
             $auditor->scan_dir = $_SESSION['auditor_scan_dir'];
             header('Content-Type: text/html');
             echo $auditor->getDiff($_POST['file']);
             exit();
        } else {
             echo "Сессия для сравнения истекла. Пожалуйста, запустите сканирование заново.";
             exit();
        }
    }

    $auditor = new OpenCartAuditor();
    $GLOBALS['auditor'] = $auditor;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
             die("Ошибка CSRF-токена.");
        }
        $date_from = !empty($_POST['date_from']) ? $_POST['date_from'] : null;
        $auditor_result = $auditor->runScans(isset($_FILES['zip']) ? $_FILES['zip'] : null, $date_from);
        $_SESSION['auditor_scan_dir'] = $auditor->scan_dir;
    }
} catch (Exception $e) {
    $error_message = $e->getMessage();
    if($auditor) $auditor->cleanup();
}

?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>OpenCart Security Auditor v4.0</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: #f8f9fa; color: #212529; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        h1, h2 { color: #0056b3; border-bottom: 2px solid #dee2e6; padding-bottom: 10px; }
        .form-container { background: #e9ecef; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: center; }
        button { background-color: #007bff; color: white; border: none; padding: 12px 25px; border-radius: 4px; font-size: 16px; cursor: pointer; transition: background-color 0.2s; }
        .tabs { display: flex; flex-wrap: wrap; border-bottom: 1px solid #ccc; margin-bottom: 20px; }
        .tab-link { padding: 10px 15px; cursor: pointer; border: 1px solid transparent; border-bottom: none; }
        .tab-link.active { border-color: #ccc; border-bottom-color: #fff; background: #fff; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 10px 12px; border: 1px solid #dee2e6; text-align: left; vertical-align: middle; }
        th { background-color: #f2f2f2; }
        .stats { margin-bottom: 15px; }
        .stats span { margin-right: 20px; font-weight: bold; }
        .actions-cell { white-space: nowrap; width: 1%; }
        .diff-btn { cursor: pointer; color: #007bff; text-decoration: underline; font-size: 0.9em; }
        .vt-check-btn { cursor: pointer; background: #6c757d; color: white; border: none; padding: 4px 8px; font-size: 0.8em; border-radius: 3px; }
        .vt-check-btn:hover { background: #5a6268; }
        .vt-check-btn:disabled { background: #adb5bd; cursor: not-allowed; }
        .vt-ok { color: green; font-weight: bold; }
        .vt-danger { color: red; font-weight: bold; }
        .vt-unknown, .vt-not-found { color: #6c757d; }
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); }
        .modal-content { background: #fefefe; margin: 5% auto; padding: 20px; border: 1px solid #888; width: 80%; max-height: 80vh; overflow-y: auto; display: flex; flex-direction: column; }
        .modal-header { padding-bottom: 10px; border-bottom: 1px solid #ccc; }
        .modal-body { flex-grow: 1; overflow-y: auto; margin-top: 15px; }
        .close-btn { float: right; color: #aaa; font-size: 28px; font-weight: bold; cursor: pointer; }
        .diff-added { background-color: #e6ffed; display: block; }
        .diff-deleted { background-color: #ffeef0; display: block; }
        pre { white-space: pre-wrap; word-wrap: break-word; font-family: monospace; }
        .error-box { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .info-box { background-color: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        #vt-api-key { width: 100%; box-sizing: border-box; padding: 8px; border: 1px solid #ccc; border-radius: 4px; font-family: monospace; margin-top: 5px; }
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ OpenCart Security Auditor v4.0</h1>
    <?php if ($error_message): ?>
        <div class="error-box"><?= $error_message ?></div>
    <?php endif; ?>

    <div class="info-box">
        <label for="vt-api-key"><b><span style="font-size: 1.2em;">🔑</span> VirusTotal API Ключ</b></label><br>
        <input type="text" id="vt-api-key" placeholder="Введите ваш VirusTotal API ключ здесь">
        <small>Ключ нужен для работы кнопок "Проверить на VT". Он сохранится в вашем браузере. <a href="https://www.virustotal.com/gui/user/signup" target="_blank">Получить ключ бесплатно</a>.</small>
    </div>

    <form method="post" enctype="multipart/form-data" id="scan-form">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
        <div class="form-container">
            <div class="form-grid">
                <div>
                    <label for="zip"><b>1. Сравнение с оригиналом (необязательно):</b></label><br>
                    <input type="file" name="zip" id="zip" accept=".zip">
                    <small>Загрузите ZIP-архив с чистой версией OpenCart.</small>
                </div>
                <div>
                    <label for="date_from"><b>2. Поиск по дате изменения (необязательно):</b></label><br>
                    <input type="date" name="date_from" id="date_from" value="<?= isset($_POST['date_from']) ? htmlspecialchars($_POST['date_from']) : '' ?>">
                    <small>Показать файлы, измененные после этой даты.</small>
                </div>
            </div>
            <p><b>3. Сканер кода</b> будет запущен автоматически.</p>
            <hr>
            <button type="submit">🚀 Запустить проверки</button>
        </div>
    </form>

    <?php if ($auditor_result): ?>
    <div class="results-container">
        <div class="tabs">
            <span class="tab-link active" onclick="openTab(event, 'integrity')">Сравнение (<?= $auditor_result['stats']['integrity']['modified'] + $auditor_result['stats']['integrity']['missing'] ?>)</span>
            <span class="tab-link" onclick="openTab(event, 'malware')">Сканер кода (<?= $auditor_result['stats']['malware'] ?>)</span>
            <span class="tab-link" onclick="openTab(event, 'date')">Поиск по дате (<?= $auditor_result['stats']['date'] ?>)</span>
        </div>

        <div id="integrity" class="tab-content active">
            <h2>Результаты сравнения с оригиналом</h2>
            <div class="stats">
                <span>Проверено: <?= $auditor_result['stats']['integrity']['total'] ?></span>
                <span style="color:green;">Совпадают: <?= $auditor_result['stats']['integrity']['ok'] ?></span>
                <span style="color:red;">Изменены: <?= $auditor_result['stats']['integrity']['modified'] ?></span>
                <span style="color:orange;">Отсутствуют: <?= $auditor_result['stats']['integrity']['missing'] ?></span>
            </div>
             <?php if (!empty($auditor_result['results']['integrity'])): ?>
            <table>
                 <thead><tr><th>Файл</th><th>Статус</th><th class="actions-cell">Действия</th></tr></thead>
                <?php foreach ($auditor_result['results']['integrity'] as $r): ?>
                <tr>
                    <td><?= htmlspecialchars($r['file']) ?></td>
                    <td><?= htmlspecialchars($r['status']) ?></td>
                    <td class="actions-cell">
                        <?php if ($r['type'] == 'modified'): ?>
                            <span class="diff-btn" data-file="<?= htmlspecialchars($r['file']) ?>">Показать различия</span> | 
                            <button class="vt-check-btn" data-file="<?= htmlspecialchars($r['file']) ?>">Проверить на VT</button>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
            </table>
            <?php elseif($auditor_result['stats']['integrity']['total'] > 0): ?>
                <p style="color:green; text-align:center;">🎉 Все файлы совпадают с оригиналом!</p>
            <?php else: ?>
                 <p style="text-align:center;">Сравнение не проводилось. Загрузите ZIP-архив, чтобы запустить его.</p>
            <?php endif; ?>
        </div>

        <div id="malware" class="tab-content">
            <h2>Найдены подозрительные конструкции в коде</h2>
            <?php if (!empty($auditor_result['results']['malware'])): ?>
            <table>
                <thead><tr><th>Файл</th><th>Тип угрозы</th><th>Шаблон</th><th class="actions-cell">Действие</th></tr></thead>
                <?php foreach ($auditor_result['results']['malware'] as $r): ?>
                <tr>
                    <td><?= htmlspecialchars($r['file']) ?></td>
                    <td><?= htmlspecialchars($r['pattern']) ?></td>
                    <td><small><?= htmlspecialchars($r['code']) ?></small></td>
                    <td class="actions-cell">
                        <button class="vt-check-btn" data-file="<?= htmlspecialchars($r['file']) ?>">Проверить на VT</button>
                    </td>
                </tr>
                <?php endforeach; ?>
            </table>
            <?php else: ?>
                <p style="color:green; text-align:center;">✅ Подозрительных конструкций в коде не найдено.</p>
            <?php endif; ?>
        </div>
        
        <div id="date" class="tab-content">
            <h2>Файлы, измененные после <?= htmlspecialchars($_POST['date_from'] ?? 'указанной даты') ?></h2>
             <?php if (!empty($auditor_result['results']['date'])): ?>
             <table>
                <thead><tr><th>Файл</th><th>Дата изменения</th></tr></thead>
                <?php foreach ($auditor_result['results']['date'] as $r): ?>
                <tr><td><?= htmlspecialchars($r['file']) ?></td><td><?= $r['date'] ?></td></tr>
                <?php endforeach; ?>
            </table>
            <?php else: ?>
                <p style="text-align:center;">Файлов, измененных после указанной даты, не найдено, или дата не была указана.</p>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>
</div>

<div id="diff-modal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <span class="close-btn">×</span>
            <h3 id="diff-modal-title">Различия в файле</h3>
        </div>
        <div class="modal-body">
            <div id="diff-output"></div>
        </div>
    </div>
</div>

<script>
function openTab(evt, tabName) {
    let i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tab-content");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName("tab-link");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
    }
    document.getElementById(tabName).style.display = "block";
    evt.currentTarget.className += " active";
}

document.addEventListener('DOMContentLoaded', () => {
    const modal = document.getElementById('diff-modal');
    const closeBtn = modal.querySelector('.close-btn');
    const apiKeyInput = document.getElementById('vt-api-key');

    if (localStorage.getItem('vt_api_key')) {
        apiKeyInput.value = localStorage.getItem('vt_api_key');
    }

    apiKeyInput.addEventListener('input', function() {
        localStorage.setItem('vt_api_key', this.value);
    });
    
    document.body.addEventListener('click', function(event) {
        if (event.target.classList.contains('diff-btn')) {
            const btn = event.target;
            const file = btn.getAttribute('data-file');
            if (!file) return;

            document.getElementById('diff-modal-title').innerText = 'Различия в файле: ' + file;
            document.getElementById('diff-output').innerHTML = '<p>Загрузка...</p>';
            modal.style.display = 'block';

            const formData = new FormData(document.getElementById('scan-form'));
            formData.append('action', 'get_diff');
            formData.append('file', file);
            
            fetch('', { method: 'POST', body: formData })
            .then(response => response.ok ? response.text() : Promise.reject('Network response was not ok.'))
            .then(data => { document.getElementById('diff-output').innerHTML = data; })
            .catch(error => { document.getElementById('diff-output').innerHTML = '<p style="color:red;">Ошибка загрузки: ' + error + '</p>'; });
        }

        if (event.target.classList.contains('vt-check-btn')) {
            const btn = event.target;
            const file = btn.getAttribute('data-file');
            const apiKey = apiKeyInput.value;

            if (!file) {
                alert('Не удалось получить имя файла для проверки.');
                return;
            }
            if (!apiKey) {
                apiKeyInput.focus();
                apiKeyInput.style.borderColor = 'red';
                alert('Пожалуйста, введите ваш API ключ для VirusTotal в поле вверху страницы.');
                return;
            }
            apiKeyInput.style.borderColor = '';
            
            const parentCell = btn.parentElement;

            btn.disabled = true;
            btn.innerHTML = 'Проверка...';

            const formData = new FormData();
            formData.append('action', 'check_virustotal');
            formData.append('file', file);
            formData.append('api_key', apiKey);
            formData.append('csrf_token', '<?= htmlspecialchars($_SESSION['csrf_token']) ?>');

            fetch('', { method: 'POST', body: formData })
            .then(response => response.ok ? response.json() : Promise.reject('Network response was not ok.'))
            .then(data => {
                if (data.error) {
                    parentCell.innerHTML = `<span class="vt-danger">${data.error}</span>`;
                } else {
                    let statusHTML = '';
                    const reportLink = `https://www.virustotal.com/gui/file/${data.hash}`;

                    // [REFINED] New logic for VT result display
                    if (data.positives > 0) {
                        // Case 1: DANGEROUS - show everything + link to report
                        statusHTML = `
                            <span class="${data.status_class}">
                                ${data.status_text} (${data.positives}/${data.total})
                            </span>
                            <a href="${reportLink}" target="_blank" style="text-decoration:none;" title="Смотреть полный отчет на VirusTotal">🔗</a>
                        `;
                    } else if (data.status_class === 'vt-not-found') {
                        // Case 2: NOT FOUND - show message with manual upload link (already included in status_text)
                        statusHTML = `<span class="${data.status_class}">${data.status_text}</span>`;
                    } else {
                        // Case 3: CLEAN - show text and score, NO link
                        statusHTML = `
                            <span class="${data.status_class}">
                                ✅ ${data.status_text} (${data.positives}/${data.total})
                            </span>
                        `;
                    }
                    parentCell.innerHTML = statusHTML;
                }
            })
            .catch(error => {
                parentCell.innerHTML = `<span class="vt-danger">Ошибка JS</span>`;
                alert('Ошибка при обращении к скрипту: ' + error);
            });
        }
    });

    closeBtn.onclick = () => { modal.style.display = "none"; }
    window.onclick = (event) => {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    }
});
</script>

</body>
</html>