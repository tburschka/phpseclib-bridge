<?php

namespace phpseclibBridge\Tests;

use phpseclib\Net\SCP;
use phpseclib\Net\SFTP;
use phpseclib\Net\SSH2;
use phpseclibBridge\Bridge;

class BridgeTest extends \PHPUnit_Framework_TestCase
{

    public function providerSetter()
    {
        return array(
            array(
                'property' => 'timeout',
                'value'    => 10
            ),
            array(
                'property' => 'hostname',
                'value'    => 'localhost'
            ),
            array(
                'property' => 'port',
                'value'    => 22
            ),
            array(
                'property' => 'auth',
                'value'    => Bridge::AUTH_KEYFILE
            ),
            array(
                'property' => 'username',
                'value'    => 'root'
            ),
            array(
                'property' => 'password',
                'value'    => 'qwertzuiop'
            ),
            array(
                'property' => 'passwordfile',
                'value'    => '~/password'
            ),
            array(
                'property' => 'keyfile',
                'value'    => '~/.ssh/id_rsa'
            ),
        );
    }

    /**
     * @dataProvider providerSetter
     * @param string $property
     * @param mixed $value
     */
    public function testSetter($property, $value)
    {
        $bridge = new Bridge();
        $reflection = new \ReflectionProperty($bridge, $property);
        $reflection->setAccessible(true);
        $this->assertNull($reflection->getValue($bridge));
        $setter = 'set' . ucfirst($property);
        $bridge->$setter($value);
        $this->assertEquals($value, $reflection->getValue($bridge));
    }

    public function testGetRealPath()
    {
        $bridge = new Bridge();
        $reflection = new \ReflectionMethod($bridge, 'getRealPath');
        $reflection->setAccessible(true);

        $absolutePath = '/home/user/.ssh/id_rsa';
        $this->assertEquals($absolutePath, $reflection->invoke($bridge, $absolutePath));

        $home = getenv('HOME');
        $relativePath = '~/.ssh/id_rsa';
        $this->assertStringStartsWith($home, $reflection->invoke($bridge, $relativePath));
        $this->assertStringEndsWith(substr($relativePath, 1), $reflection->invoke($bridge, $relativePath));
    }

    public function providerGetPassword()
    {
        return array(
            array(
                'input' => 'password',
                'output' => 'password',
            ),
            array(
                'input' => "\tsome password\r\n",
                'output' => 'some password',
            ),
            array(
                'input' => "lastPassword\0\x0B",
                'output' => 'lastPassword',
            ),
        );
    }

    /**
     * @dataProvider providerGetPassword
     * @param string $input
     * @param string $output
     */
    public function testGetPassword($input, $output)
    {
        $bridge = new Bridge();
        $bridge->setPassword($input);

        $reflection = new \ReflectionMethod($bridge, 'getPassword');
        $reflection->setAccessible(true);
        $this->assertEquals($output, $reflection->invoke($bridge));
    }

    /**
     * @dataProvider providerGetPassword
     * @param string $input
     * @param string $output
     */
    public function testGetPasswordFromPasswordfile($input, $output)
    {
        $file = tempnam(sys_get_temp_dir(), 'phpseclibBridge');
        file_put_contents($file, $input);

        $bridge = new Bridge();
        $bridge->setPasswordfile($file);

        $reflection = new \ReflectionMethod($bridge, 'getPassword');
        $reflection->setAccessible(true);
        $this->assertEquals($output, $reflection->invoke($bridge));
        unlink($file);
    }

    public function providerKeyfile()
    {
        return array(
            array(
                'file'     => __DIR__ . '/_files/id_rsa_no_passphrase',
                'password' => null,
            ),
            array(
                'file'     => __DIR__ . '/_files/id_rsa_passphrase',
                'password' => 'phpseclibBridge',
            ),
        );
    }

    /**
     * @dataProvider providerKeyfile
     * @param string $file
     */
    public function testGetKeyfile($file)
    {
        $keyfileData = file_get_contents($file);
        $bridge = new Bridge();
        $bridge->setKeyfile($file);

        $reflection = new \ReflectionMethod($bridge, 'getkeyfile');
        $reflection->setAccessible(true);
        $this->assertEquals($keyfileData, $reflection->invoke($bridge));
    }

    public function providerAuth()
    {
        return array(
            array(
                'username' => 'user',
                'password' => 'password',
            ),
        );
    }

    public function testAuth()
    {
        $username = 'user';
        $mock = $this->getMockBuilder('\\phpseclib\\Net\\SSH2')
            ->disableOriginalConstructor()
            ->getMock();
        $mock->expects($this->once())
            ->method('login')
            ->with($username)
            ->willReturn(true);

        $bridge = new Bridge();
        $bridge->setAuth(Bridge::AUTH_PASSWORD);
        $bridge->setUsername($username);

        $reflection = new \ReflectionMethod($bridge, 'auth');
        $reflection->setAccessible(true);
        $this->assertEquals($mock, $reflection->invoke($bridge, $mock));
    }

    public function testAuthWithPassword()
    {
        $username = 'user';
        $password = 'pass';
        $mock = $this->getMockBuilder('\\phpseclib\\Net\\SSH2')
            ->disableOriginalConstructor()
            ->getMock();
        $mock->expects($this->once())
            ->method('login')
            ->with($username, $password)
            ->willReturn(true);

        $bridge = new Bridge();
        $bridge->setAuth(Bridge::AUTH_PASSWORD);
        $bridge->setUsername($username);
        $bridge->setPassword($password);

        $reflection = new \ReflectionMethod($bridge, 'auth');
        $reflection->setAccessible(true);
        $this->assertEquals($mock, $reflection->invoke($bridge, $mock));
    }

    /**
     * @dataProvider providerKeyfile
     * @param string $file
     * @param mixed $password
     */
    public function testAuthWithKeyfile($file, $password)
    {
        $username = 'user';
        $mock = $this->getMockBuilder('\\phpseclib\\Net\\SSH2')
            ->disableOriginalConstructor()
            ->getMock();
        $mock->expects($this->once())
            ->method('login')
            ->with($username, $this->anything())
            ->willReturn(true);

        $bridge = new Bridge();
        $bridge->setAuth(Bridge::AUTH_KEYFILE);
        $bridge->setUsername($username);
        $bridge->setKeyfile($file);
        if ($password) {
            $bridge->setPassword($password);
        }

        $reflection = new \ReflectionMethod($bridge, 'auth');
        $reflection->setAccessible(true);
        $this->assertEquals($mock, $reflection->invoke($bridge, $mock));
    }

    public function testAuthException()
    {
        $mock = $this->getMockBuilder('\\phpseclib\\Net\\SSH2')
            ->disableOriginalConstructor()
            ->getMock();
        $mock->expects($this->once())
            ->method('login')
            ->willReturn(false);

        $bridge = new Bridge();
        $bridge->setAuth(Bridge::AUTH_PASSWORD);
        $bridge->setUsername('user');
        $bridge->setHostname('localhost');
        $bridge->setPort(22);

        $reflection = new \ReflectionMethod($bridge, 'auth');
        $reflection->setAccessible(true);
        $this->setExpectedException('Exception', 'SSH authentication (password) with user on localhost:22 failed!');
        $reflection->invoke($bridge, $mock);
    }

    public function testGetConnector()
    {
        require_once __DIR__ . '/_files/ConnectorDummy.php';

        $className = 'ConnectorDummy';
        $hostname = 'localhost';
        $port = 22;
        $timeout = 10;

        $bridge = new Bridge();

        $reflection = new \ReflectionMethod($bridge, 'getConnector');
        $reflection->setAccessible(true);
        /* @var \ConnectorDummy $connector */
        $connector = $reflection->invokeArgs($bridge, array($className, $hostname, $port, $timeout));
        $this->assertEquals($className, get_class($connector));
        $this->assertEquals($hostname, $connector->hostname);
        $this->assertEquals($port, $connector->port);
        $this->assertEquals($timeout, $connector->timeout);
    }

    public function testSsh()
    {
        $mockSsh = $this->getMockBuilder('\\phpseclib\\Net\\SSH2')
            ->disableOriginalConstructor()
            ->getMock();
        $mockSsh->expects($this->once())
            ->method('login')
            ->willReturn(true);

        $mockBridge = $this->getMockBuilder('phpseclibBridge\Bridge')
            ->setMethods(array('getConnector'))
            ->getMock();
        $mockBridge->expects($this->once())
            ->method('getConnector')
            ->willReturn($mockSsh);

        /* @var Bridge $mockBridge */
        $mockBridge->setAuth(Bridge::AUTH_PASSWORD);
        $mockBridge->setUsername('user');
        $this->assertEquals($mockSsh, $mockBridge->ssh());
    }

    public function testScp()
    {
        $mockSsh = $this->getMockBuilder('\\phpseclib\\Net\\SSH2')
            ->disableOriginalConstructor()
            ->getMock();

        $mockBridge = $this->getMockBuilder('phpseclibBridge\Bridge')
            ->setMethods(array('ssh'))
            ->getMock();
        $mockBridge->expects($this->once())
            ->method('ssh')
            ->willReturn($mockSsh);

        /* @var Bridge $mockBridge */
        $mockBridge->setAuth(Bridge::AUTH_PASSWORD);
        $mockBridge->setUsername('user');
        $this->assertInstanceOf('\\phpseclib\\Net\\SCP', $mockBridge->scp());
    }

    public function testSftp()
    {
        $mockSftp = $this->getMockBuilder('\\phpseclib\\Net\\SFTP')
            ->disableOriginalConstructor()
            ->getMock();
        $mockSftp->expects($this->once())
            ->method('login')
            ->willReturn(true);

        $mockBridge = $this->getMockBuilder('phpseclibBridge\Bridge')
            ->setMethods(array('getConnector'))
            ->getMock();
        $mockBridge->expects($this->once())
            ->method('getConnector')
            ->willReturn($mockSftp);

        /* @var Bridge $mockBridge */
        $mockBridge->setAuth(Bridge::AUTH_PASSWORD);
        $mockBridge->setUsername('user');
        $this->assertEquals($mockSftp, $mockBridge->sftp());
    }
}