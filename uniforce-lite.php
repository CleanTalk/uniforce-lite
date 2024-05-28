<?php

define('APP_NAME', 'Uniforce Lite');
define('APP_CORE_FILE', 'https://github.com/CleanTalk/php-usp/archive/refs/heads/For-uniforce-lite.zip');

// entry point
CTSecurityScanRouter::matchRoute();

/**
 * The routing for the scan.
 */
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

        define('APP_DEV_MODE', $dev_mode);

        if ( ! UniforceLiteApp::isHashExist() ) {
            echo CTSecurityScanView::renderPreload();
            exit();
        }

        CTSecurityScanView::renderScanPage();
        exit();
    }
}

/**
 * The view for the scan.
 */
class UniforceLiteApp
{
    /**
     * Generates a URL-friendly slug from the application name.
     *
     * This method converts the application name defined by the constant APP_NAME
     * to a lowercase string with spaces replaced by hyphens.
     *
     * @return string The URL-friendly slug of the application name.
     */
    public static function getAppSlug()
    {
        return strtolower(str_replace(' ', '-', APP_NAME));
    }

    /**
     * Retrieves the filename of the application.
     *
     * This method generates a filename for the application by converting the application name
     * to a URL-friendly slug and appending the '.php' extension.
     *
     * @return string The filename of the application.
     */
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
    public static function generateAppDirectory()
    {
        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;
        if ( !is_dir($dir_name) ) {
            mkdir($dir_name);
            file_put_contents($dir_name . 'index.php', '<?php' . PHP_EOL);
        }
    }

    /**
     * Downloads and unzips the application core file.
     *
     * This method handles the process of downloading the application core file from a remote URL
     * and then unzipping it into the appropriate directory.
     *
     * @return void
     */
    public static function downloadApp()
    {
        self::getRemoteFile(APP_CORE_FILE, APP_NAME);
        self::unzipApp(APP_NAME);
    }

    /**
     * Unzips the specified application archive into a directory.
     *
     * @param string $app_archive The name of the archive file to unzip.
     * @return void
     * @throws Exception If there is an error opening the archive.
     */
    public static function unzipApp($app_archive)
    {
        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;
        $zip = new ZipArchive();
        $res = $zip->open($dir_name . $app_archive);
        if ( $res === true ) {
            $zip->extractTo($dir_name);
            $zip->close();
            unlink($dir_name . $app_archive);
            return;
        }
        throw new Exception('Error code: ' . $res);
    }

    /**
     * Downloads a remote file and saves it locally.
     *
     * @param string $url The URL of the remote file to download.
     * @param string $source_file_name The name to save the downloaded file as.
     * @return void
     * @throws Exception If the URL is invalid or if there are errors with file operations.
     */
    public static function getRemoteFile($url, $source_file_name)
    {
        if (!ini_get('allow_url_fopen')) {
            throw new Exception('allow_url_fopen is not enabled. Please enable it in your PHP configuration.');
        }

        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new Exception('Invalid URL: ' . $url);
        }

        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;

        if (!file_exists($dir_name . $source_file_name)) {
            $contents = file_get_contents($url);
            if ($contents === false) {
                throw new Exception('Error downloading file from URL: ' . $url);
            }
            file_put_contents($dir_name . $source_file_name, $contents);
        }
    }
}

/**
 * The view for the scan.
 */
class CTSecurityScanView
{
    /**
     * @var string
     */
    public static $preloadUrl = "https://github.com/CleanTalk/ct-security-scan/raw/dev/preload.html";

    /**
     * Render preload HTML layout.
     *
     * @return string
     * @throws Exception If there is an error downloading or reading the preload HTML file.
     */
    public static function renderPreload()
    {
        if (!ini_get('allow_url_fopen')) {
            throw new Exception('allow_url_fopen is not enabled. Please enable it in your PHP configuration.');
        }

        $preload = file_get_contents(self::$preloadUrl);
        if ($preload === false) {
            throw new Exception('Error downloading or reading the preload HTML file.');
        }

        $token = UniforceLiteApp::generateToken();
        $html_addition = '<script>var ct_sec_token = "' . $token . '";</script>';
        $preload = preg_replace('/<\/body>(\s|<.*>)*<\/html>\s*$/i', $html_addition . '</body></html>', $preload, 1);

        return $preload;
    }

    /**
     * Render Scanner HTML layout.
     *
     * @return void
     */
    public static function renderScanPage()
    {
        UniforceLiteApp::generateAppDirectory();
        UniforceLiteApp::downloadApp();
        self::generateScanPage();
    }

    /**
     * Generate Scanner HTML layout.
     */
    public static function generateScanPage()
    {
        $uniforce_path = substr(basename(__FILE__), 0, -4) . '/php-usp-For-uniforce-lite/uniforce';
        $protocol = ! in_array($_SERVER['HTTPS'], ['off', '']) || $_SERVER['SERVER_PORT'] == 443 ? 'https://' : 'http://';
        $port = $_SERVER['SERVER_PORT'] == 80 ? '' : ':' . $_SERVER['SERVER_PORT'];
        $host = $_SERVER['HTTP_HOST'];

        header("Location: {$protocol}{$host}{$port}/{$uniforce_path}/router.php?uniforce_lite=1&tab=malware_scanner");
        exit();
    }
}
