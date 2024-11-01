<?php
/**
Plugin Name: WPDoctor Malware Scanner & Vulnerability Checker Lite
Plugin URI: https://wordpress.org/plugins/wpinfecscanlite/
description: Based on the most frequently detected malware detection patterns, this plug-in can exhaustively scan program files on the site to detect malware and vulnerability.
Version: 1.1
Text Domain: wpinfecscanlite
Domain Path: /languages
Author: wordpressdr
Author URI: https://wp-doctor.jp/
License: GPLv2 or later
*/
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function wpinfectlitescanner_isactive(){
    return true;
}


//////////cron_schedules
function wpinfectlitescanner_cronschedules($schedules){
    if(!isset($schedules["infecscannerlite10min"])){
        $schedules["infecscannerlite10min"] = array(
            'interval' => 10*60,
            'display' => esc_html(__('All files are continuously scanned every 10 minutes after designated time.','wpinfecscanlite')));
    }
    return $schedules;
}
add_filter('cron_schedules','wpinfectlitescanner_cronschedules');


function wpinfectlitescanner_repeatfunction() {
    
	require_once('scannerdata/wpinfectlitescanner.php');
    
    $scanner=new wpinfectlitescanner_MalwareScannerLite();
    $scanner->timezone=get_option('timezone_string');
    $scanner->run(ABSPATH,true,450); 
    
}

add_action ('wpinfectlitescannercronjob', 'wpinfectlitescanner_repeatfunction'); 


function wpinfectlitescannercron_activation() {
	if( !wp_next_scheduled( 'wpinfectlitescannercronjob' ) ) {  
	   wp_schedule_event( time(), 'infecscannerlite10min', 'wpinfectlitescannercronjob' );  
	}
}
add_action('wp', 'wpinfectlitescannercron_activation');


function wpinfectlitescanner_plugin_activate() {
    wpinfectlitescanner_registermysettings();
}
register_activation_hook( __FILE__, 'wpinfectlitescanner_plugin_activate' );

function wpinfectlitescannercron_deactivate() {	
	$timestamp = wp_next_scheduled ('wpinfectlitescannercronjob');
	wp_unschedule_event ($timestamp, 'wpinfectlitescannercronjob');
    
    global $wpdb;
    $table_name = $wpdb->prefix . 'infectscannerlitedata';
    $sql = $wpdb->prepare("DROP TABLE IF EXISTS %1s", $table_name);
    $wpdb->query($sql); ////edited

    delete_option( 'wpinfectlitescanner_thedbversion' );


    delete_option( 'wpinfectlitescanner_cron_autoscan_info' );
    delete_option( 'wpinfectlitescanner_cron_starttime_info' );
    delete_option( 'wpinfectlitescanner_cron_mailsend_info' );
    delete_option( 'wpinfectlitescanner_cron_mailaddr_info' );
    delete_option( 'wpinfectlitescanner_cron_lastemailsend_info' );
    delete_option( 'wpinfectlitescanner_hidealert_info' );
    
    delete_option( 'wpinfectlitescanner_valncheck');
    delete_option( 'wpinfectlitescanner_valnchecktime');
    
} 
register_deactivation_hook (__FILE__, 'wpinfectlitescannercron_deactivate');

////////////////

/////AJAX///////

function wpinfectlitescanner_realtimerun(){

    if ( ! current_user_can( 'manage_options' ) ) {
        die();
    }
    
    if ( ! check_ajax_referer('wpinfecscanlite', 'nonce', false)) {
        die();
    }
    
    require_once('scannerdata/wpinfectlitescanner.php');
    $scanner=new wpinfectlitescanner_MalwareScannerLite();
    $scanner->timezone=get_option('timezone_string');
    $res=explode(":",$scanner->run(ABSPATH,false,120));
    
    if($res[0]=="doneok"){
        $data['status'] = "doneok";
        echo wp_json_encode($data);
    }else{
        $data['status']="error";
        $data['d1'] = $res[1];
        echo wp_json_encode($data);
    }

    die();
}
add_action( 'wp_ajax_wpinfectlitescanner_realtimerun', 'wpinfectlitescanner_realtimerun' );

function wpinfectlitescanner_valncheck(){
    
    if ( ! current_user_can( 'manage_options' ) ) {
        die();
    }
    
    if ( ! check_ajax_referer('wpinfecscanlite', 'nonce', false)) {
        die();
    }
    
    $chackdata=sanitize_text_field($_POST['chackdata']);

    if(empty($chackdata)){
        die();
    }
    
    $checkdata = json_decode(hex2bin(str_rot13($chackdata)),false);
    
    $vulnerabilitiestxt = file_get_contents(__DIR__ . "/scannerdata/vulnerabilities.json");
    $vulnerabilities = json_decode($vulnerabilitiestxt);
    
    
    if($checkdata && count($vulnerabilities)>10){
        
        $resultdata=array();
        
        foreach($checkdata as $onedata){
            if(count($onedata)!=4){
                continue;
            }
            
            $dataname = trim($onedata[0]);
            $type= trim($onedata[1]);
            $versiondata = trim($onedata[2]);
            
            $foundvaln = false;
            $cve = "";
            
            foreach($vulnerabilities as $vulnerabilitie){
                if($vulnerabilitie->productdataname == $dataname){
                    $valnversion = explode("\n",$vulnerabilitie->versioninfo);
                    for($i=0;$i<count($valnversion);$i++){
                        $ptn = trim($valnversion[$i]);
                        if (strlen($ptn)>1){
                            $ptnar = explode(" ",$ptn);
                            if(strpos($ptn,'&') === false){
                                $hikaku = "";
                                $versionhikaku = "";
                                for($ii=0;$ii<count($ptnar);$ii++){
                                    if(strpos(trim($ptnar[$ii]),'>') !== false || strpos(trim($ptnar[$ii]),'<') !== false || strpos(trim($ptnar[$ii]),'=') !== false){
                                        $hikaku=trim($ptnar[$ii]);
                                    }
                                    if (preg_match("/[0-9]/", trim($ptnar[$ii]))) {
                                        $versionhikaku=trim($ptnar[$ii]);
                                    }
                                }
                                if($hikaku=="="){
                                    $hikaku="==";
                                }
                                if($hikaku!="" && $versionhikaku!=""){
                                   
                                    $versionresult = version_compare($versiondata,$versionhikaku,$hikaku);
                                    
                                    if($versionresult){
                                        $cve.=$vulnerabilitie->cveid.",";
                                        $foundvaln=true;
                                    }
                                }
                            }else{
                                $ptnar=explode("&",$ptn);
                                $ptnar1 = explode(" ",$ptnar[0]);
                                $ptnar2 = explode(" ",$ptnar[1]);
                                $hikaku1 = "";
                                $versionhikaku1 = "";
                                $hikaku2 = "";
                                $versionhikaku2 = "";
                                for($ii=0;$ii<count($ptnar1);$ii++){
                                    if(strpos(trim($ptnar1[$ii]),'>') !== false || strpos(trim($ptnar1[$ii]),'<') !== false || strpos(trim($ptnar1[$ii]),'=') !== false){
                                        $hikaku1=trim($ptnar1[$ii]);
                                    }
                                    if (preg_match("/[0-9]/", trim($ptnar1[$ii]))) {
                                        $versionhikaku1=trim($ptnar1[$ii]);
                                    }
                                }
                                for($ii=0;$ii<count($ptnar2);$ii++){
                                    if(strpos(trim($ptnar2[$ii]),'>') !== false || strpos(trim($ptnar2[$ii]),'<') !== false || strpos(trim($ptnar2[$ii]),'=') !== false){
                                        $hikaku2=trim($ptnar2[$ii]);
                                    }
                                    if (preg_match("/[0-9]/", trim($ptnar2[$ii]))) {
                                        $versionhikaku2=trim($ptnar2[$ii]);
                                    }
                                }
                                if($hikaku1=="="){
                                    $hikaku1="==";
                                }
                                if($hikaku2=="="){
                                    $hikaku2="==";
                                }
                                if($hikaku1!="" && $versionhikaku1!="" && $hikaku2!="" && $versionhikaku2!=""){
                                    $versionresult = version_compare($versiondata,$versionhikaku1,$hikaku1);
                                    
                                    $versionresult2 = version_compare($versiondata,$versionhikaku2,$hikaku2);
                                    
                                    if($versionresult || $versionresult2){
                                        $cve.=$vulnerabilitie->cveid.",";
                                        $foundvaln=true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            if($foundvaln){
                $resultdata[]=array($onedata[0],$onedata[1],$onedata[2],$cve,$onedata[3]);
            }else{
                $resultdata[]=array($onedata[0],$onedata[1],$onedata[2],"0",$onedata[3]);
            }
                
            
        }
        
        if(is_array($resultdata)){
            update_option( 'wpinfectlitescanner_valncheck',json_encode($resultdata));
            update_option( 'wpinfectlitescanner_valnchecktime',date_i18n ("Y/m/d H:i:s"));
        }
        
        echo json_encode($resultdata);
    }
    
    die();
}
add_action( 'wp_ajax_wpinfectlitescanner_valncheck', 'wpinfectlitescanner_valncheck' );

include_once('scannerdata/getscanprocess_inc.php');

function wpinfectlitescanner_infeccodegetter(){
    
    if ( ! current_user_can( 'manage_options' ) ) {
        die();
    }
    
    if ( ! check_ajax_referer('wpinfecscanlite', 'nonce', false)) {
        die();
    }
            
    $fpath=sanitize_text_field($_POST['pfile']);
    $ffile=sanitize_text_field($_POST['gfile']);

    if(!isset($fpath)){
        die();
    }

    if(!isset($ffile)){
        die();
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'infectscannerlitedata';
            
    $query = $wpdb->prepare( "SELECT * FROM %1s where filepath = %s and filename = %s and infectedflag=1 LIMIT 1;",$table_name,$fpath,$ffile);
    
    $rows = $wpdb->get_results($query);////edited
    if($wpdb->num_rows>0){
        
        if (! file_exists(ABSPATH.$fpath.$ffile)) {
            echo "nofile";
            die();
        }
                      
        $fileContent = htmlspecialchars (file_get_contents(ABSPATH.$fpath.$ffile));
        $fileContent = base64_encode ($fileContent);
        
        echo esc_html($fileContent);
                                                
    }
    
    die();
}
add_action( 'wp_ajax_wpinfectlitescanner_infeccodegetter', 'wpinfectlitescanner_infeccodegetter' );


function wpinfectlitescanner_infecwhitelist(){

    if ( ! current_user_can( 'manage_options' ) ) {
        die();
    }
    
    if ( ! check_ajax_referer('wpinfecscanlite', 'nonce', false)) {
        die();
    }
    
    $fpath = sanitize_text_field($_POST['pfile']);
    $ffile = sanitize_text_field($_POST['gfile']);
    $hash = sanitize_text_field($_POST['hash']);

    if(!isset($fpath)){
        echo "fail";
        die();
    }

    if(!isset($ffile)){
        echo "fail";
        die();
    }
    
    if(!isset($hash)){
        echo "fail";
        die();
    }
    
    if(strlen($hash)<30){
        echo "fail";
        die();
    }

    $userwhitelist = get_option( 'wpinfectlitescanner_userwhitelist',"");
    if($userwhitelist==""){
        $userwhitelist = array();
    }else{
        if(! is_array($userwhitelist)){
			$userwhitelist = unserialize($userwhitelist);
		}
    }
    $userwhitelist [] = array($fpath,$ffile,$hash);
    $userwhitelist = serialize($userwhitelist);

    $res = update_option( 'wpinfectlitescanner_userwhitelist', $userwhitelist );
     
    if($res){
        global $wpdb;
        $table_name = $wpdb->prefix . 'infectscannerlitedata';
        $sqld = $wpdb->prepare( "DELETE FROM `%1s` WHERE `%1s`.`filehash` = %s",$table_name,$table_name,$hash);
        $wpdb->get_results($sqld);////edited
        echo "ok";
    }else{
       echo "fail";
    }
    
    die();
}
add_action( 'wp_ajax_wpinfectlitescanner_infecwhitelist', 'wpinfectlitescanner_infecwhitelist' );

function wpinfectlitescanner_deletewhitelist(){

    if ( ! current_user_can( 'manage_options' ) ) {
        die();
    }
    
    if ( ! check_ajax_referer('wpinfecscanlite', 'nonce', false)) {
        die();
    }
    
    $hash=sanitize_text_field($_POST['hash']);
    
    if(!isset($hash)){
        echo "fail";
        die();
    }
    
    if(strlen($hash)<30){
        echo "fail";
        die();
    }

    $userwhitelist = get_option( 'wpinfectlitescanner_userwhitelist',"");
    if(! is_array($userwhitelist)){
		$userwhitelist = unserialize($userwhitelist);
	}
    $newuserwhitelist = array();
    foreach($userwhitelist as $ws){
        if($ws[2]!=$hash){
            $newuserwhitelist[]=$ws;
        }
    }
    if(empty($newuserwhitelist)){
        $newuserwhitelist = "";
    }
    
    $res = update_option( 'wpinfectlitescanner_userwhitelist', $newuserwhitelist );
    
    if($res){
        echo "ok";
    }else{
       echo "fail";
    }
    
    die();
}
add_action( 'wp_ajax_wpinfectlitescanner_deletewhitelist', 'wpinfectlitescanner_deletewhitelist' );


function wpinfectlitescanner_adminnoticeerror() {
    
    if ( !current_user_can( 'manage_options' ) )  {
		return;
	}
    
    $ar = get_option( 'wpinfectlitescanner_hidealert_info' ,-1 );
    
    if($ar!=1){
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'infectscannerlitedata';
        $query = $wpdb->prepare("SHOW TABLES LIKE %s", $table_name);
        if($wpdb->get_var($query) == $table_name) { ////edited
            $query = $wpdb->prepare("SELECT COUNT(id) FROM %1s where infectedflag=1;",$table_name);
            $rows = $wpdb->get_var($query); ////edited
            if ($rows>0){
                $class = 'notice notice-error';
                $message = esc_html(__("Detected malware infection. Please check from [Malware Scan lite] in the administration display.",'wpinfecscanlite')) ;

                printf( '<div class="%1$s"><p>%2$s</p></div>', esc_attr( $class ), esc_html( $message ) ); 
            }
        }
    }
}

add_action( 'load-index.php', 
    function(){
        add_action( 'admin_notices', 'wpinfectlitescanner_adminnoticeerror' );
    }
);

add_action( 'admin_menu', 'wpinfectlitescanner_pluginmenu' );

function wpinfectlitescanner_registermysettings() { 

    register_setting( 'wpinfecscanlitener-group', 'wpinfectlitescanner_cron_autoscan_info' );
    register_setting( 'wpinfecscanlitener-group', 'wpinfectlitescanner_cron_starttime_info' );
    register_setting( 'wpinfecscanlitener-group', 'wpinfectlitescanner_cron_mailsend_info' );
    register_setting( 'wpinfecscanlitener-group', 'wpinfectlitescanner_cron_mailaddr_info' );
    register_setting( 'wpinfecscanlitener-group', 'wpinfectlitescanner_cron_lastemailsend_info' );
    register_setting( 'wpinfecscanlitener-group', 'wpinfectlitescanner_hidealert_info' );
    
    register_setting( 'wpinfecscanlitener-group', 'wpinfectlitescanner_userwhitelist' );
    
    
    $setting_autoscan = get_option( 'wpinfectlitescanner_cron_autoscan_info',-1);
    if($setting_autoscan===-1){
        update_option( 'wpinfectlitescanner_cron_autoscan_info', '1' );
    }
    
    $setting_autoscantime = get_option( 'wpinfectlitescanner_cron_starttime_info' ,-1);
    if($setting_autoscantime===-1){
        update_option( 'wpinfectlitescanner_cron_starttime_info', '3' );
    }
    
    $setting_email = get_option( 'wpinfectlitescanner_cron_mailsend_info' ,-1);
    if($setting_email===-1){
        update_option( 'wpinfectlitescanner_cron_mailsend_info', '0' );
    }
    
    $setting_emailaddr = get_option( 'wpinfectlitescanner_cron_mailaddr_info',-1);
    if($setting_emailaddr===-1){
        update_option( 'wpinfectlitescanner_cron_mailaddr_info', get_option( 'admin_email' ) );
    }
    
    $hidealert = get_option( 'wpinfectlitescanner_hidealert_info',-1);
    if($hidealert===-1){
        update_option( 'wpinfectlitescanner_hidealert_info', 0 );
    }
    
    $userwhitelist = get_option( 'wpinfectlitescanner_userwhitelist',-1);
    if($userwhitelist===-1){
        update_option( 'wpinfectlitescanner_userwhitelist', "" );
    }
    
    global $wpdb;
    $table_name = $wpdb->prefix . 'infectscannerlitedata';
    $query = $wpdb->prepare("SHOW TABLES LIKE %s",$table_name);
    if($wpdb->get_var($query) != $table_name) { ////edited
        require_once('scannerdata/wpinfectlitescanner.php');
        $scanner=new wpinfectlitescanner_MalwareScannerLite();
        $scanner->wpinfectlitescan_dbinstall();
    }
}

function wpinfectlitescanner_pluginmenu() {
    
    if ( current_user_can( 'manage_options' ) )  {
        $batch =  '';
         global $wpdb;
         $table_name = $wpdb->prefix . 'infectscannerlitedata';
         $query = $wpdb->prepare("SHOW TABLES LIKE %s", $table_name);
         if($wpdb->get_var($query) == $table_name) { ////edited
            $query = $wpdb->prepare("SELECT COUNT(id) FROM %1s where infectedflag = 1", $table_name);
            $rows = $wpdb->get_var($query); ////edited
            $totalcount = 0;
            if ($rows>0){
                $totalcount = $rows;
            }
            
            
            if ($totalcount>0){
                $batch =  '<span class="update-plugins count-'.$totalcount.'"><span class="plugin-count">'.$totalcount.'</span></span>';
            }
         }
         

        add_menu_page( "WP malware scanner Lite", esc_html(__("Malware scan lite",'wpinfecscanlite')).$batch, 'manage_options', "wpdoctorinfecscannerlite","wpinfectlitescanner_pluginoptions",plugin_dir_url( __FILE__ )."/images/menuicon.png");
        add_action( 'admin_init', 'wpinfectlitescanner_registermysettings' );

    }
    
}

function wpinfectlitescanner_pluginoptions() {
    
	if ( !current_user_can( 'manage_options' ) )  {
		wp_die( esc_html(__('You do not have sufficient permissions to access this page.','wpinfecscanlite')) );
	}

    $settingchanged = false;
    $settingname = "";
    if(isset($_POST["settingname"])){
        $settingname = sanitize_text_field($_POST["settingname"]);
    }

    if(isset($settingname)){
        
        if(isset($_REQUEST['setting_save_nonce_field']) && wp_verify_nonce($_REQUEST['setting_save_nonce_field'], 'setting_save')){
        
            if($settingname=="setting"){
                $autoscan=0;
                if(isset($_POST["wpinfectlitescanner_cron_autoscan_info"])){
                    $autoscan = sanitize_text_field($_POST["wpinfectlitescanner_cron_autoscan_info"]);
                }
                $autoscantime= sanitize_text_field($_POST["wpinfectlitescanner_cron_starttime_info"]);
                $scanmailsend = 0;
                if(isset($_POST["wpinfectlitescanner_cron_mailsend_info"])){
                    $scanmailsend = sanitize_text_field($_POST["wpinfectlitescanner_cron_mailsend_info"]);
                }
                $scanmailaddr=0;
                if(isset($_POST["wpinfectlitescanner_cron_mailaddr_info"])){
                    $scanmailaddr= sanitize_text_field($_POST["wpinfectlitescanner_cron_mailaddr_info"]);
                }
                $ar=0;
                if(isset($_POST[ 'wpinfectlitescanner_hidealert_info' ])){
                    $ar = sanitize_text_field($_POST[ 'wpinfectlitescanner_hidealert_info' ]);
                }

                if($autoscan!=1){
                    $autoscan = 0;
                }
                
                
                if($autoscantime<0 || $autoscantime>23){
                    $autoscantime = 3;
                }
                
                if($scanmailsend!=1){
                    $scanmailsend =0;
                }
                
                if(! is_email($scanmailaddr)){
                    $scanmailaddr=get_option( 'admin_email' );
                }
                
                if($ar!=1){
                    $ar=0;
                }
                
                update_option( 'wpinfectlitescanner_cron_autoscan_info', $autoscan);
                update_option( 'wpinfectlitescanner_cron_starttime_info', $autoscantime );
                update_option( 'wpinfectlitescanner_cron_mailsend_info', $scanmailsend );
                update_option( 'wpinfectlitescanner_cron_mailaddr_info', $scanmailaddr );
                update_option( 'wpinfectlitescanner_hidealert_info', $ar );
                
                $settingchanged=true;
            
            }
        
        }
        
    }

    $setting_autoscan = get_option( 'wpinfectlitescanner_cron_autoscan_info',-1 );
    if($setting_autoscan===-1){
        update_option( 'wpinfectlitescanner_cron_autoscan_info', '1' );
        $setting_autoscan = 1;
    }
    
    $setting_autoscantime = get_option( 'wpinfectlitescanner_cron_starttime_info' ,-1 );
    if($setting_autoscantime===-1){
        update_option( 'wpinfectlitescanner_cron_starttime_info', '3' );
        $setting_autoscantime = 3;
    }
    
    $setting_email = get_option( 'wpinfectlitescanner_cron_mailsend_info' ,-1 );
    if($setting_email===-1){
        update_option( 'wpinfectlitescanner_cron_mailsend_info', '0' );
        $setting_email = 0;
    }
    
    $setting_emailaddr = get_option( 'wpinfectlitescanner_cron_mailaddr_info',-1  );
    if($setting_emailaddr===-1){
        update_option( 'wpinfectlitescanner_cron_mailaddr_info', get_option( 'admin_email' ) );
        $setting_emailaddr = get_option( 'admin_email' );
    }
    
    $setting_hidealert = get_option( 'wpinfectlitescanner_hidealert_info',-1  );
    if( $setting_hidealert===-1){
        update_option( 'wpinfectlitescanner_hidealert_info', 0 );
        $setting_hidealert = get_option( 'wpinfectlitescanner_hidealert_info' );
    }
    
    if ( function_exists( 'set_time_limit' ) ) {
        @set_time_limit(60*10);
    }
    
    $scanok = false;
    if(isset($_POST["dir"])){ 
        if (md5(ABSPATH)==sanitize_text_field($_POST["dir"])) {
            $scanok = true;
        }
    }
    
    
    
?>
    
	<link href="<?php echo esc_url(plugin_dir_url( __FILE__ )); ?>Styles/bootstrap.min.css" rel="stylesheet">
	<link href="<?php echo esc_url(plugin_dir_url( __FILE__ )); ?>Styles/fontawesome/font-awesome.min.css" rel="stylesheet">
    
	<script src="<?php echo esc_url(plugin_dir_url( __FILE__ )); ?>Scripts/bootstrap.min.js"></script>
    <script src="<?php echo esc_url(plugin_dir_url( __FILE__ )); ?>Scripts/ace-noconflict/ace.js" type="text/javascript" charset="utf-8"></script>
    
    <style>
    .table td, .table th {
        font-size: 14px !important;
    }
    input[type="checkbox"], input[type="radio"] {
        margin: 0px 4px 0px 0px;
    }
    #scanresult td img {
        float:left;
    }
    #scanresult td .mfound {
        display: flex;
        align-items: center;
        font-weight:bold;
        color:#f99a45;
    }
    #scanresult td .mfound2 {
        display: flex;
        align-items: center;
        font-weight:bold;
        color:#999999;
    }
    #scanresult td .mfound2 mt{
        color:#ee1100;
    }
    #showinfectfiles td small,#scanresult td small {
        display:block;
        clear:both;
    }
    @media screen and (max-width: 550px) {
        .nav {
            padding-left:2px;
            padding-right:2px;
        }
        .nav li {
            display:block !important;
            width:100%;
            margin:0px;
        }
        .nav li.active {
            border-bottom:1px solid #ddd!important;
            margin: 0px;
        }
    }
    #wpwrap{
        background-color:white;
    }
    .modal.fade {
        z-index: 10000000 !important;
    }
    .modal-dialog {
        max-width: 600px;
    }
    .nav-item{
        margin-bottom:0px !important;
    }
    </style>
    
	<div class="container" style="max-width:1000px">
		<div style="width:100%;height:261px;background-image: url('<?php echo plugin_dir_url( __FILE__ ); ?>images/<?php esc_html_e("title_en.png",'wpinfecscanlite'); ?>');background-repeat: no-repeat;">

			<form action="" method='post'>
				<?php if($scanok) { ?>
                    <p><small style="font-size:12px"><?php echo esc_html(__("*Scanning may take up to 10 minutes to complete. Please wait for a moment.",'wpinfecscanlite'));?></small></p>
					<div class="lead" id="scank" style="clear:both;float:right;margin-top:68px"><i class="fa fa-circle-o-notch fa-spin"></i> <?php esc_html_e("Scanning in progress","wpinfecscanlite"); ?></div>
				<?php }else{ ?>
				<p class="lead"></p>
                
                <p><small style="font-size:12px">Version 1.1</small></p>
                    
					<p class="lead">
						<input type="hidden" name="dir" value="<?php echo esc_html(md5(ABSPATH));////edited2 ?>" class="form-control">
					</p>
					<div style="float:right;margin-top:66px">
						<input type="submit" class="btn btn-lg btn-success" value="<?php esc_html_e("Start scanning","wpinfecscanlite"); ?>">
					</div>
                    
				<?php } ?>
			</form>
		</div>


        <ul class="nav nav-tabs" style="margin-bottom:25px">
            <li class="nav-item"><a href="#ContentA" data-bs-toggle="tab" class="nav-link active"><?php esc_html_e('Malware scan','wpinfecscanlite'); ?></a></li>
            <li class="nav-item"><a href="#ContentD" data-bs-toggle="tab" class="nav-link"><?php esc_html_e('Whitelist','wpinfecscanlite'); ?></a></li>
            <li class="nav-item"><a href="#ContentE" data-bs-toggle="tab" class="nav-link"><?php esc_html_e('Vulnerability check','wpinfecscanlite'); ?></a></li>
            <li class="nav-item"><a href="#ContentB" id="ContentBtab" data-bs-toggle="tab" class="nav-link"><?php esc_html_e('Setting','wpinfecscanlite'); ?></a></li>
            <li class="nav-item"><a href="#ContentC" data-bs-toggle="tab" class="nav-link"><?php esc_html_e('Detect more recent malware','wpinfecscanlite'); ?></a></li>
        </ul>

		<div>
            <div class="tab-content" style="display:block">
                <?php require_once('tab_malwrescan.php'); ?>
                <?php require_once('tab_whitelist.php'); ?>
                <?php require_once('tab_valn.php'); ?>
                <?php require_once('tab_setting.php'); ?>
                <?php require_once('tab_morefuture.php');?>
            </div>  
            <script>
            
            var editor;
            var nowfilepath;
            var nowfilename;
            var nowtid;
            var loadok = false;
            var codeshowing = true;
            function showcode(filepath,filename,highlight,tid){
                loadok = false;
                jQuery.ajax({
                   type: "POST",
                   url: "<?php echo admin_url( 'admin-ajax.php'); ?>",
                   data: "pfile="+filepath+"&gfile="+filename+"&action=wpinfectlitescanner_infeccodegetter&nonce=<?php echo esc_html(wp_create_nonce('wpinfecscanlite')); ?>",
                   success: function(msg){
                       if(msg =="nofile"){
                           alert("<?php echo esc_html(__("Couldn't open the file.",'wpinfecscanlite')); ?>");
                       }else{
                            jQuery('#myModalLabel').html(filepath+filename);
                            jQuery('.modal-body').html("<div style='width:100%;height:400px' id='infeccode'></div>");
                            jQuery('#myModal').modal('show');
                            jQuery('#infeccode').html(decodeURIComponent(escape(window.atob(msg))));
                            editor = ace.edit("infeccode");
                            editor.setTheme("ace/theme/github");
                            editor.session.setMode("ace/mode/php");
                            editor.session.setUseWrapMode(true);
                            var harray = highlight.split(',');
                            for( var i=0 ; i<harray.length ; i++ ) {
                               editor.session.addGutterDecoration(harray[i]-1,'HighlightBg');
                            }
                            nowfilepath = filepath;
                            nowfilename = filename;
                            nowtid = tid;
                            loadok = true;
                            codeshowing = true;
                            
                            jQuery('#highlighttxt').show();
                       }
                   }
                 });
            }
            
            
            function whitelistfile(filepath,filename,hash){

                if(window.confirm(filename + ' <?php echo esc_html(__(" - White list file.",'wpinfecscanlite')); ?>\n<?php echo esc_html(__("Add this file to your whitelist as safe file.",'wpinfecscanlite')); ?>')){
                   jQuery.ajax({
                   type: "POST",
                   url: "<?php echo esc_url(admin_url( 'admin-ajax.php')); ?>",
                   data: "pfile="+filepath+"&gfile="+filename+"&hash="+hash+"&action=wpinfectlitescanner_infecwhitelist&nonce=<?php echo esc_html(wp_create_nonce('wpinfecscanlite'));////edited2 ?>",
                   async: false,
                   success: function(msg){
                       if(msg=="fail"){
                           alert("<?php echo esc_html(__("Failed to whitelist the file.",'wpinfecscanlite')); ?>");
                       }else{
                           alert("<?php echo esc_html(__("Added to white list.",'wpinfecscanlite')); ?>");
                           jQuery(".class_"+hash).remove();
                           jQuery("#whitelisttable tr:last").after('<tr id="wl_'+hash+'"><td>'+filepath+'<b>'+filename+'</b></td><td>'+hash+'</td><td><a class="ceditbt whitelistbt" href="javascript:void(0);" onClick="deletewhitelist(\''+hash+'\')"><?php echo esc_html(__("Delete from whitelist",'wpinfecscanlite'));?></a></td></tr>');;
                       }
                    
                   }
                 });
                }
            }
            
            function deletewhitelist(hash){
                jQuery.ajax({
                   type: "POST",
                   url: "<?php echo esc_url(admin_url( 'admin-ajax.php')); ?>",
                   data: "hash="+hash+"&action=wpinfectlitescanner_deletewhitelist&nonce=<?php echo esc_html(wp_create_nonce('wpinfecscanlite'));////edited2 ?>",
                   async: false,
                   success: function(msg){
                       if(msg=="fail"){
                           alert("<?php echo esc_html(__("Failed to delete whitelist.",'wpinfecscanlite')); ?>");
                       }else{
                           jQuery("#wl_"+hash).remove();
                       }
                   }
                 });
            }

            <?php 
            if($settingchanged){
            ?>
            var sel = document.querySelector('#ContentBtab');
            bootstrap.Tab.getOrCreateInstance(sel).show();
            <?php 
            }
            ?>
            </script>
            <div class="col-lg-12">
                <footer class="footer" style="margin-top:30px">
                    <p> Made in Japan. BLUE GARAGE Inc. <?php esc_html_e("WordPress doctor","wpinfecscanlite");?> <a href="https://wp-doctor.jp/" target="_blank">https://wp-doctor.jp/</a></p>

                </footer>
            </div>
        </div>
	</div>


    <!-- Modal -->
    <style>
    .HighlightBg{background-color:#ff7d7d !important;color:white !important;}
    </style>
    <div class="modal fade" id="myModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
      <div class="modal-dialog" role="document">
        <div class="modal-content">
          <div class="modal-header">
            <h4 class="modal-title" id="myModalLabel" style="font-size:18px">Modal title</h4>
            <button type="button" class="btn-close close" data-bs-dismiss="modal" aria-label="Close"><span aria-hidden="true"> </span></button>
          </div>
          <p style="padding-left: 15px;"><small><?php esc_html_e("WordPress.org does not allow plugins published in the official directory to edit or delete files. For this reason, you will need to connect with FTP software and manually remove the malware, or use the Pro version of our plugin.","wpinfecscanlite");?></small></p>
          <p id='highlighttxt' style="padding-left: 15px;color:red"><small><?php esc_html_e("Highlighted pattern matched rows.","wpinfecscanlite");?></small></p>
          <div class="modal-body" style="padding: 15px;">
            
            <pre class='syntaxhighlight brush: php; ruler: true; highlight: [0]' style='width:100%;height:500px' id="infeccode">
                code here
            </pre>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><?php esc_html_e("Close","wpinfecscanlite");?></button>
          </div>
        </div>
      </div>
    </div>

<?php } ?>