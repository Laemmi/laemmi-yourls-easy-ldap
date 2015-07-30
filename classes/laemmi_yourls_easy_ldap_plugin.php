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

class laemmi_yourls_easy_ldap_plugin
{
    /**
     * Ldap
     *
     * @var null|laemmi_yourls_easy_ldap_Ldap
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
     * Construct
     *
     * @param $ldap
     * @param array $options
     */
    public function __construct($ldap, array $options = [])
    {
        $this->startSession();
        $this->_ldap = $ldap;
        $this->setOptions($options);
        $this->action();
    }

    /**
     * Set options
     *
     * @param array $options
     * @return $this
     */
    protected function setOptions(array $options)
    {
        $options = array_filter($options);
        $this->_options = array_merge($this->_options, $options);

        return $this;
    }

    /**
     * Do action
     */
    protected function action()
    {
        yourls_add_action('pre_login', [$this, 'action_pre_login']);
        yourls_add_action('logout', [$this, 'action_logout']);
        yourls_add_action('auth_successful', [$this, 'action_auth_successful']);
        yourls_add_action('yourls_ajax_accessdenied', [$this, 'action_yourls_ajax_accessdenied']);
        yourls_add_action('admin_page_before_form', [$this, 'action_admin_page_before_form']);
        yourls_add_action('admin_page_before_table', [$this, 'action_admin_page_before_table']);

        yourls_add_filter('is_valid_user', [$this, 'filter_is_valid_user']);
        yourls_add_filter('admin_links', [$this, 'filter_admin_links']);
        yourls_add_filter('table_add_row_action_array', [$this, 'filter_table_add_row_action_array']);
    }

    ####################################################################################################################

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
                $return = ['html' => yourls__('Access denied')];
                break;
            case 'delete':
                $return = ['success' => 0];
                break;
            case 'add':
            case 'edit_save':
            default:
                $return = [
                    'status' => 'fail',
                    'message' => yourls__('Access denied')
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
            } catch (laemmi_yourls_easy_ldap_Ldap_Exception $e) {
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
                yourls_add_notice(yourls__('Access denied'));
                yourls_html_head('accessdenied', yourls__('Access denied'));
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

        return array_intersect_key($data, $permissions['action']);
    }

    ####################################################################################################################

    /**
     * Helper to get allowed groups
     *
     * @return array
     */
    private function helperGetAllowedPermissions()
    {
        if($this->getSession('login')) {
            $inter = array_intersect_key($this->_options['allowed_groups'], $this->getSession('groups'));
            $permissions = [];
            foreach ($inter as $val) {
                foreach ($val as $_val) {
                    $permissions[$_val] = $_val;
                }
            }
        } else {
            $permissions = array_combine($this->_adminpermission, $this->_adminpermission);
        }

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

    private function mapLdapException(laemmi_yourls_easy_ldap_Ldap_Exception $e)
    {
       switch($e->getCode()) {
           case 1000:
           case 2000:
               $msg = 'No connection to LDAP-Server';
               break;
           case 3000:
           case 4000:
           case 5000:
           case 6000:
           case 7000:
           default:
               $msg = 'Invalid username or password';
       }

        return yourls__($msg) . (true === YOURLS_DEBUG ? ' (' . $e->getMessage() . ')' : '');
    }

    ####################################################################################################################

    /**
     * Get request value
     *
     * @param $key
     * @return null
     */
    private function getRequest($key)
    {
        return isset($_REQUEST[$key]) ? $_REQUEST[$key] : null;
    }

    /**
     * Set request value
     *
     * @param $key
     * @param $val
     */
    private function setRequest($key, $val)
    {
        $_REQUEST[$key] = $val;
    }

    /**
     * Start session
     */
    private function startSession()
    {
        session_start();
    }

    /**
     * Set session value
     *
     * @param $key
     * @param $value
     */
    private function setSession($key, $value)
    {
        $_SESSION['laemmi']['easy_ldap'][$key] = $value;
    }

    /**
     * Get session value
     *
     * @param $key
     * @return bool
     */
    private function getSession($key)
    {
        return isset($_SESSION['laemmi']['easy_ldap'][$key]) ? $_SESSION['laemmi']['easy_ldap'][$key] : false;
    }

    /**
     * Reset session
     */
    private function resetSession()
    {
        unset($_SESSION['laemmi']['easy_ldap']);
    }
}