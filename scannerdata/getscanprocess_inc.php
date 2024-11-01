<?php
if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

function wpinfectlitescanner_getscanprocess(){
   
    if ( ! current_user_can( 'manage_options' ) ) {
        die();
    }
    
    if ( ! check_ajax_referer('wpinfecscanlite', 'nonce', false)) {
        die();
    }
    
    global $wpdb;
    $table_name = $wpdb->prefix . 'infectscannerlitedata';
    
    $query = $wpdb->prepare("SHOW TABLES LIKE %s", $table_name);
    if($wpdb->get_var($query) != $table_name) { ////edited
        echo esc_html('{"d1":0,"d2":0,"d3":""}');////edited2
        die();
    }
    
    $datestarttime = sanitize_text_field($_POST['starttime']);
    
    if(! ($datestarttime === date("Y-m-d H:i:s", strtotime($datestarttime)))){
        die();
    }

    $query = $wpdb->prepare("SELECT COUNT(id) FROM %1s where lastchecked > %s;",$table_name,$datestarttime);
    $rows = $wpdb->get_var($query); ////edited

    if($rows==null){
        $rows=0;
    }
    $data['d1'] = $rows;

    $query = $wpdb->prepare("SELECT COUNT(id) FROM %1s where lastchecked > %s and infectedflag=1;",$table_name,$datestarttime);
    $rows = $wpdb->get_var($query); ////edited

    if($rows==null){
        $rows=0;
    }
    $data['d2'] = 0;

    if($rows>0){
        
        $query =  $wpdb->prepare("SELECT * FROM %1s where lastchecked > %s and infectedflag > 0 order by dataadddate limit 255;",$table_name,$datestarttime);;
        $rowsfiles = $wpdb->get_results($query); ////edited
        $purl = plugin_dir_url( __DIR__ );
        $homedir = ABSPATH;
        $dbinfecdata="";

        foreach ($rowsfiles as $row) 
        {
            $infeccount = count(explode(",",$row->matchline))-1;

            if($row->infectedflag==1){
                
                $dbinfecdata=$dbinfecdata."<tr id='detect_".esc_html($row->id)."' class='class_".esc_html($row->filehash)."'><td><span class='dashicons dashicons-portfolio' style='font-size: 20px;color:#ababab;'></span><td>".esc_html($row->filepath)."<b>".esc_html($row->filename)."</b></td><td><div class='mfound'><img src='".esc_html($purl)."images/".esc_html(__('patternmatched.png','wpinfecscanlite'))."'>". esc_html(__("This data contains malicious code patterns.",'wpinfecscanlite'))."</div><small>*" . $infeccount ." ". esc_html(__("Pattern matched",'wpinfecscanlite'))."</small></td><td><a class='ceditbt' href='javascript:void(0);' onClick='showcode(\"".esc_html($row->filepath)."\",\"".esc_html($row->filename)."\",\"".esc_html($row->matchline)."\",\"detect_".esc_html($row->id)."\")'><span class='dashicons dashicons-format-aside'></span><br>".esc_html(__("Display",'wpinfecscanlite'))."</a>
                </td><td><button class='autorestorebt' href='javascript:void(0);' onClick='whitelistfile(\"".esc_html($row->filepath)."\",\"".esc_html($row->filename)."\",\"".esc_html($row->filehash)."\")'><span class='dashicons dashicons-admin-post'></span><br>".esc_html(__("Add to whitelist",'wpinfecscanlite'))."</button></td></tr>"; ////edited2
                
                $data['d2']=$data['d2']+1;
                
            }
            
        }
        
        $data['d3']=$dbinfecdata;
    }
    
    echo wp_json_encode($data);
    
    die();
}
add_action( 'wp_ajax_wpinfectlitescanner_getscanprocess', 'wpinfectlitescanner_getscanprocess' );

?>