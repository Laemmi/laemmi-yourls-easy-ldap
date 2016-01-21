<?php
/*
 * Plugin URI: https://github.com/Laemmi/laemmi-yourls-easy-ldap
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * @category  laemmi-yourls-easy-ldap
 * @package   laemmi_yourls_easy_ldap_plugin.php
 * @author    Michael Lämmlein <ml@spacerabbit.de>
 * @copyright ©2015 laemmi
 * @license   http://www.opensource.org/licenses/mit-license.php MIT-License
 * @version   1.0
 * @since     21.07.15
*/

/**
 * Namespace
 */
namespace Laemmi\Yourls\Easy\Ldap;

/**
 * Use
 */
use \Laemmi\Yourls\Easy\Ldap\Ldap;
use \Laemmi\Yourls\Plugin\AbstractDefault;

/**
 * Class Plugin
 *
 * @package Laemmi\Yourls\Easy\Ldap
 */
class Plugin extends AbstractDefault
{
    /**
     * Namespace
     */
    const APP_NAMESPACE = 'laemmi-yourls-easy-ldap';

    /**
     * Ldap
     *
     * @var null|Ldap
     */
    protected $_ldap = null;

    /**
     * Options
     *
     * @var array
     */
    protected $_options = [
        'allowed_groups' => []
    ];

    /**
     * Admin permissions
     *
     * @var array
     */
    protected $_adminpermission = [
        'admin', 'tools', 'plugins', 'admin-ajax', 'action-add', 'action-edit', 'action-delete', 'action-stats', 'action-share'
    ];

    /**
     * Constructor
     *
     * @param array $options
     * @param \Laemmi\Yourls\Easy\Ldap\Ldap $ldap
     */
    public function __construct(array $options = [],Ldap $ldap)
    {
        $this->startSession();
        $this->_ldap = $ldap;
        parent::__construct($options);
    }

    ####################################################################################################################

    /**
     * Yourls action plugins_loaded
     */
    public function action_plugins_loaded()
    {
        yourls_load_custom_textdomain(self::APP_NAMESPACE, realpath(dirname( __FILE__ ) . '/../translations'));
    }

    /**
     * Yourls action pre_login
     *
     * @return bool
     */
    public function action_pre_login()
    {
        $login = $this->getSession('login');

        if($login) {
            global $yourls_user_passwords;
            $yourls_user_passwords = array_merge($yourls_user_passwords, $login);
        }

        return true;
    }

    /**
     * Yourls action logout
     */
    public function action_logout()
    {
        $this->resetSession();
    }

    /**
     * Yourls action yourls_ajax_accessdenied
     */
    public function action_yourls_ajax_accessdenied()
    {
        switch($this->getRequest('action_old')) {
            case 'edit_display':
                $return = ['html' => yourls__('Access denied', self::APP_NAMESPACE)];
                break;
            case 'delete':
                $return = ['success' => 0];
                break;
            case 'add':
            case 'edit_save':
            default:
                $return = [
                    'status' => 'fail',
                    'message' => yourls__('Access denied', self::APP_NAMESPACE)
                ];
        }

        echo json_encode($return);
    }

    /**
     * Yourls filter is_valid_user
     *
     * @param $value
     * @return bool
     */
    public function filter_is_valid_user($value)
    {
        if(true === $value) {
            return true;
        }

        $username = $this->getRequest('username');
        $password = $this->getRequest('password');

        if($username && $password) {
            try {
                $this->_ldap->auth(
                    $username,
                    $password
                );
            } catch (Exception $e) {
                yourls_login_screen($this->mapLdapException($e));
                die();
            }
            yourls_set_user($username);

            $this->setSession('login', [
                $username => 'phpass:' . yourls_phpass_hash($password)
            ]);

            $this->setSession('groups', $this->_ldap->getGroups());

            $this->action_pre_login();

            return true;
        }

        return false;
    }

    /**
     * Yourls action auth_successful
     *
     * @return bool
     */
    public function action_auth_successful()
    {
        if(!yourls_is_admin()) {
            return true;
        }

        /**
         * Check page permissions
         */
        if(preg_match('#\/admin\/(.*?)\.php#', $_SERVER['SCRIPT_FILENAME'], $matches)) {
            if (!in_array($matches[1], $this->helperGetAllowedPermissions())) {
                yourls_add_notice(yourls__('Denied access to this page', self::APP_NAMESPACE));
                yourls_html_head('accessdenied', yourls__('Denied access to this page', self::APP_NAMESPACE));
                yourls_html_logo();
                yourls_html_menu();
                yourls_html_footer();
                die();
            }
        }

        /**
         * Check action permissions
         */
        if (yourls_is_Ajax()) {
            $action = $this->getRequest('action');
            $permissions = $this->helperGetAllowedPermissions();

            $bol = false;
            switch($action) {
                case 'edit_display':
                case 'edit_save':
                    if(!in_array('edit', $permissions['action'])) {
                        $bol = true;
                    }
                    break;
                case 'add':
                case 'delete':
                    if(!in_array($action, $permissions['action'])) {
                        $bol = true;
                    }
                    break;
            }

            if($bol) {
                $this->setRequest('action_old', $action);
                $this->setRequest('action', 'accessdenied');
            }
        }
    }

    /**
     * Yourls action admin_page_before_form
     */
    public function action_admin_page_before_form()
    {
        $permissions = $this->helperGetAllowedPermissions();
        if(!isset($permissions['action']['add'])) {
            ob_start();
        }
    }

    /**
     * Yourls action admin_page_before_table
     */
    public function action_admin_page_before_table()
    {
        $permissions = $this->helperGetAllowedPermissions();
        if(!isset($permissions['action']['add'])) {
            ob_end_clean();
        }
    }

    /**
     * Yourls filter admin_links
     *
     * @param $data
     * @return array
     */
    public function filter_admin_links($data)
    {
        return array_intersect_key($data, $this->helperGetAllowedPermissions());
    }

    /**
     * Yourls filter table_add_row_action_array
     *
     * @param $data
     * @return array
     */
    public function filter_table_add_row_action_array($data)
    {
        $permissions = $this->helperGetAllowedPermissions();

        if(! isset($permissions['action']['add'])) {
            unset($data['add']);
        }
        if(! isset($permissions['action']['edit'])) {
            unset($data['edit']);
        }
        if(! isset($permissions['action']['delete'])) {
            unset($data['delete']);
        }
        if(! isset($permissions['action']['stats'])) {
            unset($data['stats']);
        }
        if(! isset($permissions['action']['share'])) {
            unset($data['share']);
        }

        return $data;
    }

    ####################################################################################################################

    /**
     * Helper to get allowed groups
     *
     * @return array
     */
    protected function helperGetAllowedPermissions()
    {
        $permissions = parent::helperGetAllowedPermissions();

        foreach($permissions as $val) {
            if('admin' === $val) {
                $permissions['index'] = 'index';
            }
            if(preg_match('/^action\-(.*)/', $val, $matches)) {
                $permissions['admin-ajax'] = 'admin-ajax';
                $permissions['action'][$matches[1]] = $matches[1];
             }
        }

        $permissions['action'] = isset($permissions['action']) ? $permissions['action'] : [];

        return $permissions;
    }

    /**
     * Map Ldap exceptions
     *
     * @param Exception $e
     * @return string
     */
    private function mapLdapException(Exception $e)
    {
       switch($e->getCode()) {
           case Ldap::ERROR_COULD_CONNECT_TO_SERVER:
           case Ldap::ERROR_COULD_NOT_BIND_TO_SERVER:
               $msg = yourls__('No connection to LDAP-Server', self::APP_NAMESPACE);
               break;
           case Ldap::ERROR_NO_SEARCH_RESULT:
           case Ldap::ERROR_NO_USER_WITH_INFORMATION_FOUND:
           case Ldap::ERROR_NO_ENTRIES_FOUND:
           case Ldap::ERROR_USER_IS_NOT_IN_ALLOWED_GROUP:
           case Ldap::ERROR_AUTH_FAILED_WRONG_PASSWORD:
           default:
               $msg = yourls__('Invalid username or password', self::APP_NAMESPACE);
       }

        return $msg . (true === YOURLS_DEBUG ? ' (' . $e->getMessage() . ')' : '');
    }
}