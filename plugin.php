<?php
/*
Plugin Name: laemmi´s easy ldap
Plugin URI: https://github.com/Laemmi/laemmi-yourls-easy-ldap
Description: Ldap authentication
Version: 1.0
Author: Michael Lämmlein
Author URI: https://github.com/Laemmi
Copyright 2015 laemmi
*/

/**
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
 * @package   plugin.php
 * @author    Michael Lämmlein <ml@spacerabbit.de>
 * @copyright ©2015 laemmi
 * @license   http://www.opensource.org/licenses/mit-license.php MIT-License
 * @version   1.0
 * @since     21.07.15
*/

// No direct call
if(!defined('YOURLS_ABSPATH'))die();

if (!yourls_is_API()) {
    require_once 'lib/Plugin.php';
    require_once 'lib/Ldap.php';
    new \Laemmi\Yourls\Easy\Ldap\Plugin(new \Laemmi\Yourls\Easy\Ldap\Ldap([
        'host' => defined('LAEMMI_EASY_LDAP_HOST') ? LAEMMI_EASY_LDAP_HOST : '',
        'port' => defined('LAEMMI_EASY_LDAP_PORT') ? LAEMMI_EASY_LDAP_PORT : '',
        'base_dn' => defined('LAEMMI_EASY_LDAP_BASE') ? LAEMMI_EASY_LDAP_BASE : '',
        'filter' => defined('LAEMMI_EASY_LDAP_FILTER') ? LAEMMI_EASY_LDAP_FILTER : '',
        'filter_group' => defined('LAEMMI_EASY_LDAP_FILTER_GROUP') ? LAEMMI_EASY_LDAP_FILTER_GROUP : '',
        'allowed_groups' => defined('LAEMMI_EASY_LDAP_ALLOWED_GROUPS') ? json_decode(LAEMMI_EASY_LDAP_ALLOWED_GROUPS, true) : [],
        'rdn_username' => defined('LAEMMI_EASY_LDAP_RDN_USERNAME') ? LAEMMI_EASY_LDAP_RDN_USERNAME : '',
        'rdn_password' => defined('LAEMMI_EASY_LDAP_RDN_PASSWORD') ? LAEMMI_EASY_LDAP_RDN_PASSWORD : ''
    ]), [
        'allowed_groups' => defined('LAEMMI_EASY_LDAP_ALLOWED_GROUPS') ? json_decode(LAEMMI_EASY_LDAP_ALLOWED_GROUPS, true) : [],
    ]);
}
