<?php

namespace phpseclibBridge;

use phpseclib\Crypt\RSA;
use phpseclib\Net\SCP;
use phpseclib\Net\SFTP;
use phpseclib\Net\SSH2;

class Bridge
{
    const AUTH_PASSWORD = 'password';
    const AUTH_KEYFILE = 'keyfile';

    const DEFAULT_PORT = 22;
    const DEFAULT_TIMEOUT = 10;

    /**
     * @var int
     */
    protected $timeout;

    /**
     * @var string
     */
    protected $hostname;

    /**
     * @var int
     */
    protected $port;

    /**
     * @var string
     */
    protected $auth;

    /**
     * @var string
     */
    protected $username;

    /**
     * @var string
     */
    protected $password;

    /**
     * @var string
     */
    protected $passwordfile;

    /**
     * @var string
     */
    protected $keyfile;

    /**
     * @param int $timeout
     */
    public function setTimeout($timeout)
    {
        $this->timeout = $timeout;
    }

    /**
     * @param string $hostname
     */
    public function setHostname($hostname)
    {
        $this->hostname = $hostname;
    }

    /**
     * @param int $port
     */
    public function setPort($port)
    {
        $this->port = $port;
    }

    /**
     * @param string $auth
     */
    public function setAuth($auth)
    {
        $this->auth = $auth;
    }

    /**
     * @param string $username
     */
    public function setUsername($username)
    {
        $this->username = $username;
    }

    /**
     * @param string $password
     */
    public function setPassword($password)
    {
        $this->password = $password;
    }

    /**
     * @param string $passwordfile
     */
    public function setPasswordfile($passwordfile)
    {
        $this->passwordfile = $passwordfile;
    }

    /**
     * @param string $keyfile
     */
    public function setKeyfile($keyfile)
    {
        $this->keyfile = $keyfile;
    }

    /**
     * @return SSH2
     */
    public function ssh()
    {
        $port = isset($this->port) ? $this->port : self::DEFAULT_PORT;
        $timeout = isset($this->timeout) ? $this->timeout : self::DEFAULT_TIMEOUT;
        return $this->auth($this->getConnector('\\phpseclib\\Net\\SSH2', $this->hostname, $port, $timeout));
    }

    /**
     * @return SCP
     */
    public function scp()
    {
        $ssh = $this->ssh();
        return new SCP($ssh);
    }

    /**
     * @return SFTP
     */
    public function sftp()
    {
        $port = isset($this->port) ? $this->port : self::DEFAULT_PORT;
        $timeout = isset($this->timeout) ? $this->timeout : self::DEFAULT_TIMEOUT;
        return $this->auth($this->getConnector('\\phpseclib\\Net\\SFTP', $this->hostname, $port, $timeout));
    }

    /**
     * @param string $className
     * @param string $hostname
     * @param integer $port
     * @param integer $timeout
     * @return SSH2|SFTP
     */
    protected function getConnector($className, $hostname, $port, $timeout)
    {
        return new $className($hostname, $port, $timeout);
    }

    /**
     * @return string
     */
    protected function getKeyfile()
    {
        return file_get_contents($this->getRealPath($this->keyfile));
    }


    /**
     * @return string
     */
    protected function getPassword()
    {
        if ($this->passwordfile) {
            $password = file_get_contents($this->getRealPath($this->passwordfile));
        } else {
            $password = $this->password;
        }
        return is_null($password) ? $password : trim($password, "\t\n\r\0\x0B");
    }

    /**
     * fixes home path notation
     *
     * @param string $file
     * @return string
     */
    protected function getRealPath($file)
    {
        if (isset($file) && '~' === $file{0}) {
            $file = getenv('HOME') . substr($file, 1);
        }
        return $file;
    }

    /**
     * @param SSH2|SFTP $connector
     * @return SSH2|SFTP
     * @throws \Exception
     */
    protected function auth($connector)
    {
        switch ($this->auth) {
            case self::AUTH_KEYFILE:
                $password = new RSA();
                if (!is_null($this->getPassword())) {
                    $password->setPassword($this->getPassword());
                }
                $password->loadKey($this->getKeyfile());
                break;
            case self::AUTH_PASSWORD: // break intentionally omitted
            default:
                $password = $this->getPassword();
                break;
        }
        if (!isset($password)) {
            $loggedIn = $connector->login($this->username);
        } else {
            $loggedIn = $connector->login($this->username, $password);
        }
        if (!$loggedIn) {
            throw new \Exception(sprintf(
                'SSH authentication (%s) with %s on %s:%s failed!',
                $this->auth,
                $this->username,
                $this->hostname,
                $this->port
            ));
        }
        return $connector;
    }
}
