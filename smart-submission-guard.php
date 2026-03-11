<?php
/*
Plugin Name: Smart Submission Guard
Description: Flags suspicious form submissions based on keywords, domains, and IP addresses.
Version: 1.0
Author: Brian Shah
*/

if (!defined('ABSPATH')) exit;

class SmartSubmissionGuard {

    private $table;

    public function __construct() {

        global $wpdb;
        $this->table = $wpdb->prefix . 'ssg_logs';

        register_activation_hook(__FILE__, [$this,'install']);

        add_action('admin_menu', [$this,'menu']);
        add_action('admin_init', [$this,'register_settings']);

        add_action('init', [$this,'capture_submission']);
    }

    public function install(){

        global $wpdb;

        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$this->table} (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255),
            ip VARCHAR(45),
            message TEXT,
            flagged_reason TEXT,
            created DATETIME DEFAULT CURRENT_TIMESTAMP
        ) $charset;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }

    public function menu(){

        add_menu_page(
            'Submission Guard',
            'Submission Guard',
            'manage_options',
            'submission-guard',
            [$this,'dashboard'],
            'dashicons-shield-alt',
            26
        );

        add_submenu_page(
            'submission-guard',
            'Settings',
            'Settings',
            'manage_options',
            'submission-guard-settings',
            [$this,'settings_page']
        );
    }

    public function register_settings(){

        register_setting('ssg_settings_group','ssg_keywords');
        register_setting('ssg_settings_group','ssg_domains');
        register_setting('ssg_settings_group','ssg_ips');

    }

    public function settings_page(){

        ?>

        <div class="wrap">
        <h1>Submission Guard Settings</h1>

        <form method="post" action="options.php">

        <?php settings_fields('ssg_settings_group'); ?>

        <table class="form-table">

        <tr>
        <th>Blocked Keywords</th>
        <td>
        <textarea name="ssg_keywords" rows="6" cols="60"><?php echo esc_textarea(get_option('ssg_keywords')); ?></textarea>
        <p class="description">Comma separated words</p>
        </td>
        </tr>

        <tr>
        <th>Blocked Email Domains</th>
        <td>
        <textarea name="ssg_domains" rows="4" cols="60"><?php echo esc_textarea(get_option('ssg_domains')); ?></textarea>
        <p class="description">Comma separated domains</p>        
        </td>
        </tr>

        <tr>
        <th>Blocked IPs</th>
        <td>
        <textarea name="ssg_ips" rows="4" cols="60"><?php echo esc_textarea(get_option('ssg_ips')); ?></textarea>
        <p class="description">Comma separated IPs</p>
        </td>
        </tr>

        </table>

        <?php submit_button(); ?>

        </form>
        </div>

        <?php
    }

    public function dashboard(){

        global $wpdb;

        $logs = $wpdb->get_results("SELECT * FROM {$this->table} ORDER BY created DESC LIMIT 100");

        ?>

        <div class="wrap">

        <h1>Flagged Submissions</h1>

        <table class="widefat striped">

        <thead>
        <tr>
        <th>Email</th>
        <th>IP</th>
        <th>Reason</th>
        <th>Date</th>
        </tr>
        </thead>

        <tbody>

        <?php foreach($logs as $log): ?>

        <tr>
        <td><?php echo esc_html($log->email); ?></td>
        <td><?php echo esc_html($log->ip); ?></td>
        <td><?php echo esc_html($log->flagged_reason); ?></td>
        <td><?php echo esc_html($log->created); ?></td>
        </tr>

        <?php endforeach; ?>

        </tbody>

        </table>

        </div>

        <?php
    }

    public function capture_submission(){

        if(empty($_POST['email']) || empty($_POST['message']))
            return;

        $email = sanitize_email($_POST['email']);
        $message = sanitize_textarea_field($_POST['message']);
        $ip = $_SERVER['REMOTE_ADDR'];

        $keywords = explode(',', get_option('ssg_keywords'));
        $domains = explode(',', get_option('ssg_domains'));
        $ips = explode(',', get_option('ssg_ips'));

        $reason = '';

        foreach($keywords as $word){

            if(stripos($message, trim($word)) !== false){

                $reason = 'Keyword match: '.$word;
                break;

            }

        }

        if(!$reason){

            $domain = substr(strrchr($email,"@"),1);

            if(in_array(trim($domain), $domains))
                $reason = 'Blocked email domain';
        }

        if(!$reason){

            if(in_array($ip,$ips))
                $reason = 'Blocked IP';
        }

        if($reason){

            global $wpdb;

            $wpdb->insert($this->table, [

                'email' => $email,
                'ip' => $ip,
                'message' => $message,
                'flagged_reason' => $reason

            ]);
        }

    }

}

new SmartSubmissionGuard();