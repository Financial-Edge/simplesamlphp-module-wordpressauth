<?php

namespace SimpleSAML\Module\wordpressauth\Auth\Process;

use PDO;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Module\wordpressauth\DB;

class EnsureUserExistsInWordpress extends ProcessingFilter
{
    private DB $db;

    public function __construct(array &$config, $reserved)
    {
        parent::__construct($config, $reserved);

        $this->db = new DB($config);
    }

    public function process(array &$state): void
    {
        Assert::keyExists($state, 'Attributes');
        Assert::keyExists($state['Attributes'], 'email');

        if (!$this->userExists($state)) {
            $this->insertUser($state);
        }
    }

    private function userExists(array $state): bool
    {
        $pdo = $this->db->getPdo();

        $statement = $pdo->prepare(sprintf('SELECT 1 FROM `%s` WHERE user_email = :email', $this->db->getUsersTable()));
        $statement->execute(['email' => $state['Attributes']['email'][0]]);

        return (bool) $statement->fetch(PDO::FETCH_ASSOC);
    }

    private function insertUser(array $state): void
    {
        $pdo = $this->db->getPdo();

        $attributes = $state['Attributes'];

        $data = [
            'user_email' => $attributes['email'][0],
            'user_nicename' => $attributes['displayName'][0] ?? $attributes['first_name'][0] ?? '',
            'user_registered' => date('Y-m-d H:m:s'),
        ];

        $data['display_name'] = $data['user_nicename'] ?: $data['user_email'];

        $pdo->prepare(sprintf(
            'INSERT INTO `%s`
                (`user_login`, `user_email`, `user_nicename`, `user_registered`, `display_name`)
                VALUES(:user_email, :user_email, :user_nicename, :user_registered, :display_name)',
            $this->db->getUsersTable()
        ))->execute($data);

        $id = $pdo->lastInsertId();

        $this->setMetaData($id, 'nickname', $data['display_name']);
        $this->setMetaData($id, $this->db->getPrefix() . 'capabilities', 'a:1:{s:10:"subscriber";b:1;}');
        $this->setMetaData($id, 'user_created_by', sprintf('FE SSO (%s)', $state['saml:sp:IdP'] ?? '?'));
        $this->setMetaDataIfValueIsNotEmpty($id, 'first_name', $attributes['first_name'][0] ?? null);
        $this->setMetaDataIfValueIsNotEmpty($id, 'last_name', $attributes['last_name'][0] ?? null);
    }

    private function setMetaData(int $userId, string $key, string $value): void
    {
        $this->db->getPdo()
            ->prepare(sprintf(
                'INSERT INTO `%s`
                (`user_id`, `meta_key`, `meta_value`)
                VALUES (?, ?, ?)',
                $this->db->getUserMetaTable()
            ))->execute([
                $userId,
                $key,
                $value
            ]);
    }

    private function setMetaDataIfValueIsNotEmpty(int $userId, string $key, ?string $value): void
    {
        if (!empty($value)) {
            $this->setMetaData($userId, $key, $value);
        }
    }
}