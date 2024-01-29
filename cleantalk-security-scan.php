<?php

CTSecurityScanRouter::matchRoute();

class CTSecurityScanRouter
{
    public static function matchRoute()
    {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $methods = [
                'prepare_file_system',
                'receive_signatures',
                'make_file_system_cast',
                'check_signatures',
            ];
            if (!isset($_POST['method']) || !in_array($_POST['method'], $methods)) {
                exit();
            }

            switch($_POST['method']) {
                case 'prepare_file_system':
                    CTSecurityScanService::prepareFS();
                    self::resp();
                    break;
                case 'receive_signatures':
                    $result = CTSecurityScanHandler::receiveSignatures();
                    self::resp($result);
                    break;
                case 'make_file_system_cast':
                    $result = CTSecurityScanHandler::makeFSCast();
                    self::resp($result);
                    break;
                case 'check_signatures':
                    $result = CTSecurityScanHandler::checkSignatures();
                    self::resp($result);
                    break;
            }

            exit();
        }

        if (!CTSecurityScanService::isHashExist()) {
            echo CTSecurityScanView::renderPreload();
            exit();
        }

        echo CTSecurityScanView::renderScanPage();
        exit();
    }

    private static function resp($data = ["status" => "OK"])
    {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data);
    }
} 

class CTSecurityScanView
{
    public static $preloadUrl = "https://raw.githubusercontent.com/CleanTalk/ct-security-scan/main/preload.html";
    // public static $preloadUrl = "preload.html";
    public static $scanUrl = "https://raw.githubusercontent.com/CleanTalk/ct-security-scan/main/scan.html";
    // public static $scanUrl = "scan.html";

    public static function renderPreload()
    {
        $preload = file_get_contents(self::$preloadUrl);
        $token = CTSecurityScanService::generateToken();
        $html_addition = '<script>var ct_sec_token = "' . $token . '";</script>';
        $preload = preg_replace('/<\/body>(\s|<.*>)*<\/html>\s*$/i', $html_addition.'</body></html>', $preload, 1);

        return $preload;
    }

    public static function renderScanPage()
    {
        return file_get_contents(self::$scanUrl);
    }
} 

class CTSecurityScanHandler
{
    public static function receiveSignatures()
    {
        $result = CTSecurityScanService::receiveSignatures();
        return $result ? ['status' => 'OK'] : ['status' => 'Fail'];
    }

    public static function makeFSCast()
    {
        $result = CTSecurityScanService::makeFSCast();
        return $result ? ['status' => 'OK'] : ['status' => 'Fail'];
    }

    public static function checkSignatures()
    {
        $result = CTSecurityScanService::checkSignatures();
        // return $result ? ['status' => 'OK'] : ['status' => 'Fail'];
        return $result;
    }
} 

class CTSecurityScanService
{
    private static $signatures_url = 'https://cleantalk-security.s3.amazonaws.com/security_signatures/security_signatures_v2.csv.gz';
    private static $signatures_file = 'signatures.csv';
    private static $scan_file = 'scan.csv';
    private static $extensions = ['php'];
    private static $max_file_size = 2621440; // 2.5 MB
    
    public static function generateToken()
    {
        $token = md5(rand(1000, 9999));
        rename(__FILE__, substr(__FILE__, 0, -4) . '_' . $token . '.php');

        return $token;
    }

    public static function isHashExist()
    {
        if (basename(__FILE__) === 'cleantalk-security-scan.php') {
            return false;
        }

        return true;
    }

    public static function prepareFS()
    {
        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;
        if (!is_dir($dir_name)) {
            mkdir($dir_name);
            file_put_contents($dir_name . 'index.php', '<?php' . PHP_EOL);
        }
    }

    public static function receiveSignatures()
    {
        $signatures = file_get_contents(self::$signatures_url);
        $content = @gzdecode($signatures);
        if ($content === false) {
            return false;
        }

        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;
        $write_result = @file_put_contents($dir_name . self::$signatures_file, $content);
        if ($write_result === false) {
            return false;
        }

        return true;
    }

    public static function makeFSCast()
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(__DIR__, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST,
            \RecursiveIteratorIterator::CATCH_GET_CHILD
        );

        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;
        $fp = fopen($dir_name . self::$scan_file, 'w');
        foreach ($iterator as $path => $dir) {
            if (in_array($dir->getExtension(), self::$extensions)) {
                $mtime = @filemtime((string)$path);
                if ( empty($mtime) ) {
                    clearstatcache($path);
                    $mtime = @filemtime((string)$path);
                    if ( empty($mtime) ) {
                        $mtime = @filectime((string)$path);
                        if ( empty($mtime) ) {
                            $mtime = time();
                        }
                    }
                }

                fputcsv($fp, [$path, $mtime]);
            }
        }
        fclose($fp);

        return true;
    }

    public static function checkSignatures()
    {
        if (!function_exists('md5')) {
            return ['status' => 'Fail', 'error' => 'function md5 not exist'];
        }

        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;
        $scan = fopen($dir_name . self::$scan_file, 'r');

        $signatures = array_map('str_getcsv', explode("\n", file_get_contents($dir_name . self::$signatures_file)));
        $verdict = [];
        while ($file = fgetcsv($scan)) {
            $path = $file[0];
            if (!file_exists($path)) {
                return ['status' => 'Fail', 'error' => 'file not exist'];
            }
            if (!is_readable($path)) {
                return ['status' => 'Fail', 'error' => 'file not readable'];
            }
            if (!self::checkFileSize($path)) {
                return ['status' => 'Fail', 'error' => 'file size zero or too large'];
            }

            $hash = md5(file_get_contents($path));


            foreach ((array)$signatures as $signature) {
                if ($signature[3] === "'FILE'") {
                    if ("'$hash'" === $signature[2]) {
                        $verdict[] = [$path, $signature[1], $file[1]];
                    }
                }
            }
        }
        fclose($scan);


        return ['status' => 'OK', 'verdict' => $verdict];
    }

    private static function checkFileSize($path)
    {
        $file_size = filesize($path);
        if (!(int)$file_size) {
            return false;
        }
        if ((int)$file_size > self::$max_file_size) {
            return false;
        }

        return true;
    }
} 
