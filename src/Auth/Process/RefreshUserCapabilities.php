<?php

namespace SimpleSAML\Module\wordpressauth\Auth\Process;

use PDO;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Module\wordpressauth\DB;

class RefreshUserCapabilities extends ProcessingFilter
{
    private DB $db;

    public function __construct(array &$config, $reserved)
    {
        parent::__construct($config, $reserved);

        $this->db = new DB($config);
    }

    public function process(array &$state): void
    {
        // This is a first time log in, or they don't have a WordPress id
        if (!array_key_exists('PreviousSSOTimestamp', $state) || !isset($state['Attributes']['wordpress_id'])) {
            return;
        }

        $pdo = $this->db->getPdo();

        $capabilities = $pdo->prepare(sprintf(
            'SELECT meta_value
                FROM %s
                WHERE user_id = :user_id
                    AND meta_key = "%scapabilities"',
            $this->db->getUserMetaTable(),
            $this->db->getPrefix()
        ));

        // Don't throw an exception as we don't want the user to get stuck in a loop
        if (!$capabilities->execute(['user_id' => $state['Attributes']['wordpress_id'][0]])) {
            return;
        }

        $state['Attributes']['capabilities'] = [$capabilities->fetch(PDO::FETCH_ASSOC)['meta_value']];
    }
}