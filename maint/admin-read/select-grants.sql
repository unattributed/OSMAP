-- Review only: provision the selected SQL identity separately before grants.
-- No global grants, DML, DDL, FILE, GRANT OPTION, or mailbox credential access.
GRANT SELECT (username,password,active,modified,superadmin) ON postfixadmin.admin TO 'osmap_admin_read'@'localhost';
GRANT SELECT (username,domain,active) ON postfixadmin.domain_admins TO 'osmap_admin_read'@'localhost';
GRANT SELECT (domain,active,aliases,mailboxes,maxquota,quota,backupmx) ON postfixadmin.domain TO 'osmap_admin_read'@'localhost';
