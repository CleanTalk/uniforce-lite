<?php

define('APP_NAME', 'Uniforce Lite');
define('APP_CORE_FILE', 'https://github.com/CleanTalk/php-usp/archive/refs/heads/For-uniforce-lite.zip');

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

        define('APP_DEV_MODE', $dev_mode);

        if ( ! UniforceLiteApp::isHashExist() ) {
            echo CTSecurityScanView::renderPreload();
            exit();
        }

        CTSecurityScanView::renderScanPage();
        exit();
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
    public static function generateAppDirectory()
    {
        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;
        if ( !is_dir($dir_name) ) {
            mkdir($dir_name);
            file_put_contents($dir_name . 'index.php', '<?php' . PHP_EOL);
        }
    }

    public static function downloadApp()
    {
        // @todo handle self::getRemoteFile errors
        self::getRemoteFile(APP_CORE_FILE, APP_NAME);
        self::unzipApp(APP_NAME);
    }

    public static function unzipApp($app_archive)
    {
        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;
        $zip = new ZipArchive();
        $res = $zip->open($dir_name . $app_archive);
        if ( $res === true ) {
            $zip->extractTo($dir_name);
            $zip->close();
            return unlink($dir_name . $app_archive);
        }
        throw new Exception('Error code: ' . $res);
    }

    public static function getRemoteFile($url, $source_file_name)
    {
        // @Todo 1) validate $url
        // @Todo 2) validate $url
        // @Todo 3) handle file_get_contents/file_put_contents errors
        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . substr(basename(__FILE__), 0, -4) . DIRECTORY_SEPARATOR;
        if ( ! file_exists($dir_name . $source_file_name) ) {
            file_put_contents($dir_name . $source_file_name, file_get_contents($url));
        }
        return  @file_get_contents($url);
    }
}

class CTSecurityScanView
{
    /**
     * @var string
     */
    public static $preloadUrl = "https://github.com/CleanTalk/ct-security-scan/raw/master/preload.html";

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
     *
     * @return void
     */
    public static function renderScanPage()
    {
        // @ToDo Strong depends on fopen wrappers https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-fopen
        // @ToDo The method have to return only a `string`. Other types must be handled as errors.
        UniforceLiteApp::generateAppDirectory();
        UniforceLiteApp::downloadApp();
        self::generateScanPage();
    }

    /**
     * @psalm-suppress UndefinedClass
     * @ToDo remove temporary psalm suppressing
     */
    public static function generateScanPage()
    {
        $uniforce_path = substr(basename(__FILE__), 0, -4) . '/php-usp-For-uniforce-lite/uniforce';
        $protocol = ! in_array($_SERVER['HTTPS'], ['off', '']) || $_SERVER['SERVER_PORT'] == 443 ? 'https://' : 'http://';
        $host = $_SERVER['HTTP_HOST'];

        header("Location: {$protocol}{$host}/{$uniforce_path}/router.php?uniforce_lite=1&tab=malware_scanner");
        exit();
    }
}