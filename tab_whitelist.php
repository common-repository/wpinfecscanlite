<?php if ( ! defined( 'ABSPATH' ) ) {exit;}?>
<div class="tab-pane" id="ContentD">
	<style>
	.whitelistbt{
		height:26px;
		padding:3px;
	}
	</style>
    <div class="col-lg-12">
          <p><?php echo esc_html(__("List of whitelist files registered as safe files.",'wpinfecscanlite'));?></p>
          <p> </p>
          <table id="whitelisttable" class="table">
          <thead>
              <tr>
              <th><?php echo esc_html(__("Files",'wpinfecscanlite'));?></th>
              <th nowrap><?php echo esc_html(__("Hash",'wpinfecscanlite'));?></th>
              <th nowrap><?php echo esc_html(__("Remove",'wpinfecscanlite'));?></th>
              </tr>
          </thead>
          <tr>
              <?php
                $userwhitelist = get_option( 'wpinfectlitescanner_userwhitelist',"");
                if($userwhitelist==""){
                    echo "<tr><td>".esc_html(__("No whitelist found.",'wpinfecscanlite'))."</td><td></td><td></td></tr>";
                }else{
                    if(! is_array($userwhitelist)){
                        $userwhitelist = unserialize($userwhitelist);
                    }
                    foreach($userwhitelist as $ws){
                        echo "<tr id='wl_".esc_html($ws[2])."'><td>".esc_html($ws[0])."<b>".esc_html($ws[1])."</b>"."</td>";
                        echo "<td>".esc_html($ws[2])."</b>"."</td>";
                        echo "<td><a class='ceditbt whitelistbt' href='javascript:void(0);' onClick='deletewhitelist(\"".esc_html($ws[2])."\")'>".esc_html(__("Delete from whitelist",'wpinfecscanlite'))."</a></td></tr>";
                    }
                }
              ?>
          </tr>
          </table>
    </div>
</div>