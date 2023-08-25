<?php

namespace SimpleSAML\Module\wordpressauth\Auth\Source;

use Exception;
use PDO;
use SimpleSAML\Error\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\core\Auth\UserPassBase;
use SimpleSAML\Module\wordpressauth\DB;
use SimpleSAML\Module\wordpressauth\Vendor\PasswordHash;

class WordpressAuth extends UserPassBase
{
    private DB $db;

    public function __construct($info, $config)
    {
        parent::__construct($info, $config);

        $this->db = new DB($config);
    }

    protected function login(string $username, string $password): array
    {
        /* Connect to the database. */
        $db = $this->db->getPdo();

        $usersTable = $this->db->getUsersTable();

        /* Prepare statement (PDO) */
        $sql = 'SELECT ID, user_login, user_pass, display_name, user_email FROM ' . $usersTable . ' WHERE user_login = :username';

        /* Check if username is email and adjust flow to accommodate */
        if (filter_var($username, FILTER_VALIDATE_EMAIL)) {
            $sql = $sql . ' OR user_email = :username';
            $sth = $db->prepare('SELECT user_login FROM ' . $usersTable . ' WHERE user_email = :username');
            $sth->execute(array('username' => $username));
            $db_username = $sth->fetchAll()[0]['user_login'] ?? null;
            $email = $username;
            $username = $db_username;
        }

        $st = $db->prepare($sql);

        if (!$st->execute(array('username' => $username))) {
            throw new Exception("Failed to query database for user.");
        }

        /* Retrieve the row from the database. */
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            /* User not found. */
            throw new Error('WRONGUSERPASS');
        }

        $hasher = new PasswordHash(8, TRUE);

        /* Check the password against the hash in Wordpress wp_users table */
        if (empty($password) || empty($row['user_pass']) || !$hasher->CheckPassword($password, $row['user_pass'])) {
            /* Invalid password. */
            throw new Error('WRONGUSERPASS');
        }

        /* Fetch first name, last name and capabilities from wp_usermeta table */
        $capabilities_key = getenv("AUTH_DB_TABLE_PREFIX") . 'capabilities';
        $meta_sql = "SELECT meta_key, meta_value FROM " . $this->db->getUserMetaTable() . " WHERE user_id = :id AND meta_key = 'first_name' OR user_id = :id AND meta_key = 'last_name' OR user_id = :id AND meta_key = '$capabilities_key'";
        $meta_st = $db->prepare($meta_sql);
        if (!$meta_st->execute(array('id' => $row['ID']))) {
            throw new Exception("Failed to query database for user.");
        }

        $meta_rows = $meta_st->fetchAll();
        foreach ($meta_rows as $meta_row) {
            if ($meta_row['meta_key'] == 'first_name') {
                $first_name = $meta_row['meta_value'] ? $meta_row['meta_value'] : "FE";
            } else if ($meta_row['meta_key'] == 'last_name') {
                $last_name = $meta_row['meta_value'] ? $meta_row['meta_value'] : "User";
            } else if ($meta_row['meta_key'] == $capabilities_key) {
                $capabilities = $meta_row['meta_value'];

            }
        }

        $email = $row['user_email'];
        Logger::warning("UID '$email' username '$username' email '$email'");

        /* Create the attribute array of the user. */
        $attributes = array(
            'uid' => array($email),
            'username' => array($username),
            'name' => array($row['display_name']),
            'display_name' => array($row['display_name']),
            'email' => array($email),
            'first_name' => array($first_name),
            'last_name' => array($last_name),
            'capabilities' => array($capabilities)
        );

        return $attributes;
    }
}
