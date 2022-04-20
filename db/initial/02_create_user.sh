mysql --user=$MYSQL_USER --password=$MYSQL_PASSWORD $MYSQL_DATABASE -P $MYSQL_TCP_PORT --execute \
"INSERT INTO users (uid, username, password, profile, isadmin) 
SELECT 1, '${ADMIN_ACCOUNT}', SHA2('${ADMIN_PASSWORD}', 512), '${ADMIN_PROFILE}', true;"