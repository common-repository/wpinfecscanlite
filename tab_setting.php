<?php if ( ! defined( 'ABSPATH' ) ) {exit;}?>
<div class="tab-pane" id="ContentB">
    <div class="col-lg-12">
          <form method="post" action="">
            <table class="form-table">
              <tr valign="top">
              <th scope="row"><?php esc_html_e("Scan automatically","wpinfecscanlite"); ?></th>
              <td><input type="checkbox" name="wpinfectlitescanner_cron_autoscan_info" value="1" <?php if($setting_autoscan==1){echo 'checked="checked"';} ?>/></td>
              <th scope="row"><?php esc_html_e("Beginning time of auto scanning","wpinfecscanlite"); ?></th>
              <td><select name="wpinfectlitescanner_cron_starttime_info" autocomplete="off"/>
              <?php
              for($i=0;$i<22;$i++){
                  $select="";
                  if($setting_autoscantime==$i){
                      $select=" selected='selected'";
                  }
                  echo "<option value='".$i."' ".$select.">".$i." ".esc_html(__("O'Clock","wpinfecscanlite"))."</option>";
              }
              ?>
              </select>
              
              </td>
              </tr>
              <tr valign="top">
              <th scope="row"><?php esc_html_e("Notify by e-mail upon detection","wpinfecscanlite");?></th>
              <td><input type="checkbox" name="wpinfectlitescanner_cron_mailsend_info" value="1" <?php if($setting_email==1){echo 'checked="checked"';} ?> /></td>
              <th scope="row"><?php esc_html_e("E-mail address","wpinfecscanlite");?></th>
              <td><input type="text" name="wpinfectlitescanner_cron_mailaddr_info" value="<?php echo esc_html($setting_emailaddr);/////edited2 ?>" /></td>
              </tr>
              
              <tr valign="top">
              <th scope="row"><?php esc_html_e("Hide detection alert on the administration display","wpinfecscanlite");?></th>
              <td><input type="checkbox" name="wpinfectlitescanner_hidealert_info" value="1" <?php if($setting_hidealert==1){echo 'checked="checked"';} ?> /></td>
              <th scope="row"></th>
              <td></td>
              </tr>
            </table>
            <input type="hidden" name="settingname" value="setting"/>
            <?php wp_nonce_field('setting_save', 'setting_save_nonce_field');?>
            <?php submit_button(); ?>
            <small><?php esc_html_e("*E-mail notification is only once in 24 hours even if detected multiple times.","wpinfecscanlite");?></small><br>
            <small><?php esc_html_e("*The beginning time of auto scanning may be different when using WordPress cron.","wpinfecscanlite");?></small>
          </form>
    </div>
</div>