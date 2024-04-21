<?php

// 1) Download uniforce from https://github.com/CleanTalk/php-usp/archive/refs/heads/For-uniforce-lite.zip
// 2) Unpack this into random-named directory
// 3) Try to generate scan page by \Cleantalk\USP\Layout\Settings::draw()

define('APP_NAME', 'Uniforce Lite');
define('APP_CORE_FILE', 'https://github.com/CleanTalk/php-usp/archive/refs/heads/For-uniforce-lite.zip');
define('APP_DEV_MODE', true);

CTSecurityScanRouter::matchRoute();

class CTSecurityScanRouter
{
    /**
     * Simple http router.
     *
     * @return void
     */
    public static function matchRoute()
    {
        $dev_mode = isset($_GET['dev_mode']) && $_GET['dev_mode'] == 1 ?: false;

        if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
            $methods = [
                'prepare_file_system',
                'receive_signatures',
                'make_file_system_cast',
                'check_signatures',
            ];
            if ( !isset($_POST['method']) || !in_array($_POST['method'], $methods) ) {
                exit();
            }

            switch ( $_POST['method'] ) {
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

        if ( ! UniforceLiteApp::isHashExist() ) {
            echo CTSecurityScanView::renderPreload();
            exit();
        }

        echo CTSecurityScanView::renderScanPage();
        exit();
    }

    /**
     * Output the JSON response.
     *
     * @param array $data
     *
     * @return void
     */
    private static function resp($data = ["status" => "OK"])
    {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data);
    }
}

class UniforceLiteApp
{
    public static function getAppSlug()
    {
        return strtolower(str_replace(' ', '-', APP_NAME));
    }

    public static function getAppFileName()
    {
        return self::getAppSlug() . '.php';
    }
    /**
     * Security unique token generating.
     *
     * @return string
     */
    public static function generateToken()
    {
        if ( APP_DEV_MODE ) {
            return '';
        }
        $token = md5((string)rand(1000, 9999));
        $token = substr($token, 0, 6);
        rename(__FILE__, substr(__FILE__, 0, -4) . '_' . $token . '.php');

        return $token;
    }

    /**
     * Checking if the main file contains unique hash in its filename.
     * Simple: is the application was installed and is ready to work.
     *
     * @return bool
     */
    public static function isHashExist()
    {
        if ( ! APP_DEV_MODE && basename(__FILE__) === self::getAppFileName() ) {
            return false;
        }

        return true;
    }

    /**
     * Makes new folder to contain scanner data.
     *
     * @return void
     */
    public static function prepareFS()
    {
        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;
        if ( !is_dir($dir_name) ) {
            mkdir($dir_name);
            file_put_contents($dir_name . 'index.php', '<?php' . PHP_EOL);
        }
    }

    public static function getRemoteFile($url)
    {

    }
}

class CTSecurityScanView
{
    /**
     * @var string
     */
    public static $preloadUrl = "https://github.com/CleanTalk/ct-security-scan/raw/master/preload.html";
    /**
     * @var string
     */
    public static $scanUrl = "https://github.com/CleanTalk/ct-security-scan/raw/master/scan.html";
    /**
     * @var string
     */
    public static $devModeScanUrl = __DIR__ . "/scan.html";

    /**
     * Render preload HTML layout.
     *
     * @return array|string|null
     */
    public static function renderPreload()
    {
        // @ToDo Strong depends on fopen wrappers https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-fopen
        $preload = file_get_contents(self::$preloadUrl);
        $token = UniforceLiteApp::generateToken();
        $html_addition = '<script>var ct_sec_token = "' . $token . '";</script>';
        $preload = preg_replace('/<\/body>(\s|<.*>)*<\/html>\s*$/i', $html_addition . '</body></html>', $preload, 1);

        // @ToDo The method have to return only a `string`. Other types must be handled as errors.
        return $preload;
    }

    /**
     * Render Scanner HTML layout.
     * @param bool $dev_mode If isset, will use self::$devModeScanUrl instead of the Github source
     * @return false|string
     */
    public static function renderScanPage($dev_mode = false)
    {
        // @ToDo Strong depends on fopen wrappers https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-fopen
        // @ToDo The method have to return only a `string`. Other types must be handled as errors.

	    self::generateAppDirectory();
		self::downloadApp();
		return self::renderScanPage();

        if ($dev_mode) {
            if (!file_exists(self::$devModeScanUrl)) {
                @file_put_contents(self::$devModeScanUrl, file_get_contents(self::$scanUrl));
            }
            $work_file = self::$devModeScanUrl;
        } else {
            $work_file = self::$scanUrl;
        }
        return file_get_contents($work_file);
    }
}



class CTSecurityScanHandler
{
    /**
     * Download and store signatures list.
     *
     * @return string[]
     */
    public static function receiveSignatures()
    {
        $result = CTSecurityScanService::receiveSignatures();
        return $result ? ['status' => 'OK'] : ['status' => 'Fail'];
    }

    /**
     * Find and store files to be scanned.
     *
     * @return string[]
     */
    public static function makeFSCast()
    {
        $result = CTSecurityScanService::makeFSCast();
        return $result;
    }

    /**
     * Check files by signature analysis.
     *
     * @return array|string[]
     */
    public static function checkSignatures()
    {
        $result = CTSecurityScanService::checkSignatures();

        // @ToDo Handle error here
        return $result;
    }
}

class CTSecurityScanService
{
    /**
     * @var string
     */
    private static $signatures_url = 'https://cleantalk-security.s3.amazonaws.com/security_signatures/security_signatures_v2.csv.gz';

    /**
     * @var string
     */
    private static $signatures_file = 'signatures.csv';

    /**
     * @var string
     */
    private static $scan_file = 'scan.csv';

    /**
     * @var string[]
     */
    private static $extensions = ['php'];

    /**
     * @var int
     */
    private static $max_file_size = 2621440; // 2.5 MB


    /**
     * Getting signatures wrapper.
     *
     * @return bool
     */
    public static function receiveSignatures()
    {
        $signatures = @file_get_contents(self::$signatures_url);

        if (false === $signatures) {
            return false;
        }

        $content = @gzdecode($signatures);
        if ( $content === false ) {
            return false;
        }

        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;

        if (!is_dir($dir_name) || !is_writable($dir_name)) {
            return false;
        }

        $write_result = @file_put_contents($dir_name . self::$signatures_file, $content);

        if ( $write_result === false ) {
            return false;
        }

        return true;
    }

    /**
     * Find files to be scanned wrapper.
     *
     * @return array
     */
    public static function makeFSCast()
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(__DIR__, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST,
            \RecursiveIteratorIterator::CATCH_GET_CHILD
        );

        $total_site_files = 0;

        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;
        $fp = fopen($dir_name . self::$scan_file, 'w');
        foreach ( $iterator as $path => $dir ) {
            if ( in_array($dir->getExtension(), self::$extensions) ) {
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
                $total_site_files++;
            }
        }
        fclose($fp);

        return array('status' => 'OK', 'total_site_files' => $total_site_files);
    }

    /**
     * Signature analyser.
     *
     * @return array|string[]
     */
    public static function checkSignatures()
    {
        if ( !function_exists('md5') ) {
            return ['status' => 'Fail', 'error' => 'function md5 not exist'];
        }

        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;
        if (!is_dir($dir_name) || !is_readable($dir_name)) {
            return ['status' => 'Fail', 'error' => 'Directory is not readable ' . $dir_name];
        }

        $csv_file_name = $dir_name . self::$scan_file;

        if (!is_file($csv_file_name) || !is_readable($csv_file_name)) {
            return ['status' => 'Fail', 'error' => 'File is not readable ' . $csv_file_name];
        }

        $scan = fopen($csv_file_name, 'r');

        if (false === $scan) {
            return ['status' => 'Fail', 'error' => 'Cannot open stream ' . $csv_file_name];
        }

        $signatures_file_name = $dir_name . self::$signatures_file;

        if (!is_file($csv_file_name) || !is_readable($csv_file_name)) {
            return ['status' => 'Fail', 'error' => 'File is not readable ' . $signatures_file_name];
        }

        $signatures_content = @file_get_contents($signatures_file_name);
        if (empty($signatures_content)) {
            return ['status' => 'Fail', 'error' => 'Signatures file is empty or damaged ' . $signatures_content];
        }

        $signatures = array_map('str_getcsv', explode("\n", $signatures_content));
        $verdict = [];
        $scanned_files_counter = 0;
        while ( $file = fgetcsv($scan) ) {
            $path = $file[0];
            if ( !file_exists($path) ) {
                return ['status' => 'Fail', 'error' => 'file not exist'];
            }
            if ( !is_readable($path) ) {
                return ['status' => 'Fail', 'error' => 'file not readable'];
            }
            if ( !self::checkFileSize($path) ) {
                continue;
            }

            $hash = md5(file_get_contents($path));


            foreach ( $signatures as $signature ) {
                if ( isset($signature[3], $signature[2], $signature[1]) && $signature[3] === "'FILE'" ) {
                    if ( "'$hash'" === $signature[2] ) {
                        $verdict[] = [$path, $signature[1], $file[1]];
                    }
                }
            }

            $scanned_files_counter++;
        }
        fclose($scan);

        unlink($dir_name . self::$signatures_file);
        self::compress($dir_name . self::$scan_file);

        return ['status' => 'OK', 'verdict' => $verdict, 'scanned_files_counter' => $scanned_files_counter];
    }

    /**
     * Compressing file to archive
     *
     * @param string $file
     * @return void
     */
    private static function compress($file)
    {
        if ( ! function_exists('gzopen')) {
            return;
        }

        //@ToDo check the file existence

        $gz = gzopen($file . '.gz', 'w9');
        gzwrite($gz, file_get_contents($file));
        gzclose($gz);

        unlink($file);
    }

    /**
     * Checking file size against allowed value `max_file_size`.
     *
     * @param string $path
     * @return bool
     */
    private static function checkFileSize($path)
    {
        $file_size = filesize($path);
        if ( !(int)$file_size ) {
            return false;
        }
        if ( (int)$file_size > self::$max_file_size ) {
            return false;
        }

        return true;
    }
}
