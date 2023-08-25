<?php

namespace SimpleSAML\Module\wordpressauth;

use Exception;
use PDO;

class DB
{
    private PDO $pdo;
    private array $config;

    public function __construct(array $config)
    {
        $this->validateConfigOption($config, 'dsn');
        $this->validateConfigOption($config, 'username');
        $this->validateConfigOption($config, 'password');
        $this->validateConfigOption($config, 'userstable');
        $this->validateConfigOption($config, 'usermetatable');

        $this->config = $config;
    }

    private function validateConfigOption(array $config, string $key): void
    {
        if (empty($config[$key]) || !is_string($config[$key])) {
            throw new Exception("Missing or invalid {$key} option in config.");
        }
    }

    public function getPdo(): PDO
    {
        if (empty($this->pdo)) {
            $this->pdo = new PDO($this->config['dsn'], $this->config['username'], $this->config['password']);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            /* Ensure that we are operating with UTF-8 encoding. */
            $this->pdo->exec("SET NAMES 'utf8'");
        }

        return $this->pdo;
    }

    public function getUsersTable(): string
    {
        return $this->config['userstable'];
    }

    public function getUserMetaTable(): string
    {
        return $this->config['usermetatable'];
    }

    public function getPrefix(): string
    {
        return $this->config['prefix'] ?? '';
    }
}