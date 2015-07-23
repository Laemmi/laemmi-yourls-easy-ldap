# laemmi-yourls-easy-ldap
ldap authentification in YOURLS with page and action permissions by ldap group

## Ldap hostname
define('LAEMMI_EASY_LDAP_HOST', '');

## Ldap port (optional) default 389
define('LAEMMI_EASY_LDAP_PORT', '');

## Ldap base
define('LAEMMI_EASY_LDAP_BASE', '');

## Ldap filter for search (optional) @default (&(uid=%s)(objectClass=posixAccount))
define('LAEMMI_EASY_LDAP_FILTER', '');

##Ldap filter for groups (optional) @default (&(memberuid=%s))
define('LAEMMI_EASY_LDAP_FILTER_GROUP', '');

##Allowed ldap groupsnames with yourls pages and action permissions
define('LAEMMI_EASY_LDAP_ALLOWED_GROUPS', json_encode([
    'MY-LDAP-GROUPNAME' => ['admin', 'tools', 'plugins', 'action-add', 'action-edit', 'action-delete', 'action-stats', 'action-share']
]));

## Ldap RDN username (optional)
define('LAEMMI_EASY_LDAP_RDN_USERNAME', '');

## Ldap RDN password (optional)
define('LAEMMI_EASY_LDAP_RDN_PASSWORD', '');

## Permissions
### Page
* admin = Admin interface
* tools = Tools
* plugins = Manage plugins

## Actions
* action-add = Add url
* action-edit = Edit url
* action-delete = Delete url
* action-stats = Show stats button
* action-share = Show share button