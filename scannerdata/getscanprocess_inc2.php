<?php
if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

$scannedfiles = 0;

global $wpdb;
$table_name = $wpdb->prefix . 'infectscannerlitedata';

$dbinfecdata="";
$noinfection = true;
$query = $wpdb->prepare("SHOW TABLES LIKE %s",$table_name);
if($wpdb->get_var($query) == $table_name) { ////edited
    
    $wpinfectlitescanner_thedbversion = get_option( 'wpinfectlitescanner_thedbversion',1.0);
    if($wpinfectlitescanner_thedbversion < 1.1){
        if(empty($scanner)){
            require_once(__DIR__.'/wpinfectlitescanner.php');
            $scanner=new wpinfectlitescanner_MalwareScannerLite();
        }
        $scanner->wpinfectlitescan_dbinstall();
    }
    
    $query = $wpdb->prepare("SELECT * FROM %1s where infectedflag > 0 limit 255;",$table_name);
    $rowsfiles = $wpdb->get_results($query); ////edited
    $purl = plugin_dir_url( __DIR__ );
    $homedir = ABSPATH;

    foreach ($rowsfiles as $row) 
    {
        $infeclines = explode(",",$row->matchline);
        $infeccount = count($infeclines)-1;
        $infeclines = array_unique($infeclines);
        
        if($row->infectedflag==1){
            
            $dbinfecdata=$dbinfecdata."<tr id='detect_".esc_html($row->id)."' class='class_".esc_html($row->filehash)."'>
            <td><span class='dashicons dashicons-portfolio' style='font-size: 20px;color:#ababab;'></span></td>
            <td>".esc_html($row->filepath)."<b>".esc_html($row->filename)."</b></td>
            <td>
            <div class='mfound'><img src='".esc_html($purl)."images/".esc_html(__('patternmatched.png','wpinfecscanlite'))."'>
            ". esc_html(__("This data contains malicious code patterns.",'wpinfecscanlite'))."</div><small>*" . esc_html($infeccount) ." ". esc_html(__("Pattern matched",'wpinfecscanlite'))."</small></td>
            <td><a class='ceditbt' href='javascript:void(0);' onClick='showcode(\"".esc_html($row->filepath)."\",\"".esc_html($row->filename)."\",\"".esc_html(implode(",",$infeclines))."\",\"detect_".$row->id."\")'><span class='dashicons dashicons-format-aside'></span><br>".esc_html(__("Display",'wpinfecscanlite'))."</a>
            </td><td><button class='autorestorebt' href='javascript:void(0);' onClick='whitelistfile(\"".esc_html($row->filepath)."\",\"".esc_html($row->filename)."\",\"".esc_html($row->filehash)."\")'><span class='dashicons dashicons-admin-post'></span><br>".esc_html(__("Add to whitelist",'wpinfecscanlite'))."</button></td>
            </tr>";////edited2
            
            $noinfection = false;
            
        }
        
    }
    
    $datebeforeoneday = date("Y-m-d H:i:s", strtotime('-24 hours', time()));
 
    $query = $wpdb->prepare("SELECT COUNT(id) FROM %1s where lastchecked > %s;",$table_name,$datebeforeoneday);
    $rows = $wpdb->get_var($query); ////edited
    if ($rows>0){
        $scannedfiles=$rows;
    }
    
    
}

echo "<b>".esc_html(__("The number of files scanned in last 24 hours",'wpinfecscanlite'))." ".esc_html($scannedfiles)." ".esc_html(__("Files",'wpinfecscanlite'))."</b><br>
<small style='color:#888'>".esc_html(__("Inspecting files that have changed contents or have passed for a certain period since the last inspection.",'wpinfecscanlite'))."</small>
<p> </p>";
echo '<table id="scanresult" class="table"><thead><tr><th nowrap></th><th>'.esc_html(__("Detected",'wpinfecscanlite'))."</th><th>".esc_html(__("Pattern matching",'wpinfecscanlite'))."</th><th nowrap>".esc_html(__("View code",'wpinfecscanlite')).'</th><th nowrap>'.esc_html(__("White list",'wpinfecscanlite')).'</th></tr></thead>';
echo $dbinfecdata;
echo "</table>"; 

if($scannedfiles>0){
    if($noinfection){
        $hmatchurl = plugin_dir_url( __DIR__ )."images/noinfect.png";
        echo "<h4 style='margin-top:25px;margin-bottom:25px;padding:0px;'><img src='".esc_html($hmatchurl)."' style='width:30px;padding:0px;'> ".esc_html(__("Not detected any malware in this website.","wpinfecscanlite"))."</h4>";
    }
}


?>