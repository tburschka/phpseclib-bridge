<?php

class ConnectorDummy
{
    public $hostname;

    public $port;

    public $timeout;

    public function __construct($hostname, $port, $timeout)
    {
        $this->hostname = $hostname;
        $this->port = $port;
        $this->timeout = $timeout;
    }
}
