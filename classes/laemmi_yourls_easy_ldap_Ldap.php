<?php
/**
 * Copyright 2007-2015 Andreas Heigl/wdv Gesellschaft für Medien & Kommunikation mbH & Co. OHG
 *
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
 * @category    laemmi-yourls-easy-ldap
 * @package     laemmi_yourls_easy_ldap_ldap.php
 * @author      Michael Lämmlein <m.laemmlein@wdv.de>
 * @copyright   ©2007-2015 Andreas Heigl/wdv Gesellschaft für Medien & Kommunikation mbH & Co. OHG
 * @license     http://www.opensource.org/licenses/mit-license.php MIT-License
 * @version     2.7.0
 * @since       21.07.15
 */

class laemmi_yourls_easy_ldap_Ldap_Exception extends Exception {};

class laemmi_yourls_easy_ldap_Ldap
{
    /**
     * Ldap connect resource
     *
     * @var null
     */
    protected $_connect = null;

    /**
     * Options
     *
     * @var array
     */
    protected $_options = [
        'host' => '',
        'port' => '389',
        'base_dn' => '',
        'filter' => '(&(uid=%s)(objectClass=posixAccount))',
        'filter_group' => '(&(memberuid=%s))',
        'allowed_groups' => [],
        'rdn_username' => '',
        'rdn_password' => '',
    ];

    /**
     * Available groups from search
     *
     * @var array
     */
    protected $_groups = [];

    /**
     * Construct
     *
     * @param array $options
     */
    public function __construct(array $options)
    {
        $this->setOptions($options);
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
     * Init connection
     *
     * @return $this
     * @throws Ldap_Exception
     * @throws laemmi_yourls_easy_ldap_Ldap_Exception
     */
    protected function init()
    {
        $this->connect();
        if($this->_options['rdn_username'] && $this->_options['rdn_password']) {
            $this->login();
        }

        return $this;
    }

    /**
     * Connect to ldap server
     *
     * @throws laemmi_yourls_easy_ldap_Ldap_Exception
     */
    protected function connect()
    {
        $this->_connect = ldap_connect($this->_options['host'], $this->_options['port']);
        if (!$this->_connect) {
           throw new laemmi_yourls_easy_ldap_Ldap_Exception('no ldap connection');
        }
    }

    /**
     * Login to ldap server
     *
     * @throws Ldap_Exception
     */
    protected function login()
    {
        $bol = ldap_bind($this->_connect, $this->_options['rdn_username'], $this->_options['rdn_password']);

        if(!$bol) {
            throw new Ldap_Exception(sprintf(
                'Could not bind to server %s. Returned Error was: [%s] %s',
                $this->_options['host'],
                ldap_errno($this->_connect),
                ldap_error($this->_connect)
            ));
        }
    }

    /**
     * Get search entries
     *
     * @param $filter
     * @param array $attributes
     * @return array
     * @throws laemmi_yourls_easy_ldap_Ldap_Exception
     */
    protected function getSearchEntries($filter, array $attributes = [])
    {
        $result = ldap_search($this->_connect, $this->_options['base_dn'], $filter, $attributes, 0, 0, 10);

        if (! $result) {
            throw new laemmi_yourls_easy_ldap_Ldap_Exception('No user with that informations found');
        }
        if (1 > ldap_count_entries($this->_connect, $result)) {
            throw new laemmi_yourls_easy_ldap_Ldap_Exception('No user with that information found');
        }
//        if (1 < ldap_count_entries($this->_connect, $result)) {
//            throw new laemmi_yourls_easy_ldap_Ldap_Exception('More than one user found with that information');
//        }

        $entries = ldap_get_entries($this->_connect, $result);
        if (false === $entries) {
            throw new laemmi_yourls_easy_ldap_Ldap_Exception('no result set found');
        }

        ldap_free_result($result);

        return $entries;
    }

    /**
     * Set available groups
     *
     * @param array $value
     */
    protected function setGroups(array $value)
    {
        $this->_groups = $value;
    }

    /**
     * Get available groups
     *
     * @return array
     */
    public function getGroups()
    {
        return $this->_groups;
    }

    /**
     * Auth username and password
     *
     * @param $username
     * @param $password
     * @return bool
     * @throws laemmi_yourls_easy_ldap_Ldap_Exception
     */
    public function auth($username, $password)
    {
        $this->init();

        /**
         * Check if user exists
         */
        $username = trim(preg_replace('/[^a-zA-Z0-9\-\_@\.]/', '', $username));
        $filter = str_replace('%s', $username, $this->_options['filter']);
        $attributes = array('uid');
        $entries = $this->getSearchEntries($filter, $attributes);
        $dn = $entries[0]['dn'];
        $uid = $entries[0]['uid'][0];

        /**
         * Check if user is in group
         */
        $filter = str_replace('%s', $uid, $this->_options['filter_group']);
        $attributes = array('cn');
        $entries = $this->getSearchEntries($filter, $attributes);
        $groups = [];
        foreach($entries as $val) {
            if(isset($val['cn'])) {
                $groups[$val['cn'][0]] = $val['cn'][0];
            }
        }
        $inter = array_intersect_key($this->_options['allowed_groups'], $groups);
        if(!$inter) {
            throw new laemmi_yourls_easy_ldap_Ldap_Exception('User is not in allowed group');
        }

        /**
         * Check user password
         */
        $link_id = @ldap_bind($this->_connect, $dn, $password);
        @ldap_close($this->_connect);
        if (false === $link_id) {
            throw new laemmi_yourls_easy_ldap_Ldap_Exception('auth failed');
        }

        $this->setGroups($groups);

        return true;
    }
}