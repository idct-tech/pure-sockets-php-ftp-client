<?php

namespace IDCT\PureFTP;

use InvalidArgumentException;

class Client
{
    protected $socket;
    protected $timeout;

    protected $data;
    protected $usePassive = false;

    public function connect($host, $port = 21, $timeout = 90)
    {
        $false = false; // We are going to return refrence (E_STRICT)

        if (!is_string($host) || !is_integer($port) || !is_integer($timeout)) {
            throw new InvalidArgumentException('Invalid data: missing host, port or wrong data type of timeout.');
        }

        $iError = 0;
        $sError = '';

        $this->socket = @fsockopen($host, $port, $iError, $sError, $timeout);
        $this->timeout = $timeout;

        if (!is_resource($this->socket)) {
            throw new FtpException('Could not connect: [' . $iError . '] ' . $sError);
        }

        stream_set_blocking($this->socket, true);
        stream_set_timeout($this->socket, $timeout);

        do {
            $content[] = fgets($this->socket, 8129);
            $array     = socket_get_status($this->socket);
        } while ($array['unread_bytes'] > 0);

        if (substr($content[count($content)-1], 0, 3) == 220) {
            return $this;
        }

        throw new FtpException('Could not connect: ' . $content);
    }

    public function login($username, $password)
    {
        $this->verifyConnection();

        if (is_null($username)) {
            throw new FtpException('Missing username.');
        }

        fputs($this->socket, 'USER '.$username."\r\n");
        $contents = [];
        do {
            $contents[] = fgets($this->socket, 8192);
            $array      = socket_get_status($this->socket);
        } while ($array['unread_bytes'] > 0);

        if (substr($contents[count($contents)-1], 0, 3) != 331) {
            throw new FtpException($contents[count($contents)-1]);
        }

        fputs($this->socket, 'PASS '.$password."\r\n");
        $contents = [];
        do {
            $contents[] = fgets($this->socket, 8192);
            $array      = socket_get_status($this->socket);
        } while ($array['unread_bytes']);

        if (substr($contents[count($contents)-1], 0, 3) == 230) {
            return $this;
        }

        throw new FtpException($contents[count($contents)-1]);
    }

    public function quit()
    {
        $this->verifyConnection();
        fputs($this->socket, 'QUIT'."\r\n");
        fclose($this->socket);
        $this->socket = null;

        return $this;
    }

    public function close()
    {
        return $this->quit();
    }

    public function pwd()
    {
        $this->verifyConnection();
        fputs($this->socket, 'PWD'."\r\n");

        $content = [];
        do {
            $content[] = fgets($this->socket, 8192);
            $array     = socket_get_status($this->socket);
        } while ($array['unread_bytes'] > 0);

        if (substr($cont = $content[count($content)-1], 0, 3) == 257) {
            $pos  = strpos($cont, '"')+1;
            $pos2 = strrpos($cont, '"') - $pos;
            $path = substr($cont, $pos, $pos2);

            return $path;
        }

        throw new FtpException($content);
    }

    public function chdir($pwd)
    {
        $this->verifyConnection();

        if (!is_string($pwd)) {
            throw new FtpException('Missing path.');
        }

        fputs($this->socket, 'CWD '.$pwd."\r\n");
        $content = [];
        do {
            $content[] = fgets($this->socket, 8192);
            $array     = socket_get_status($this->socket);
        } while ($array['unread_bytes'] > 0);

        if (substr($content[count($content)-1], 0, 3) == 250) {
            return $this;
        }

        throw new FtpException($content);
    }

    public function pasv($pasv)
    {
        $this->verifyConnection();

        if (!is_bool($pasv)) {
            throw new InvalidArgumentException('Argument must be of type bool.');
        }

        // If data connection exists, destroy it
        if ($this->data !== null) {
            fclose($this->data);
            $this->data = null;

            do {
                fgets($this->socket, 16);
                $array = socket_get_status($this->socket);
            } while ($array['unread_bytes'] > 0);
        }

        // Are we suppost to create active or passive connection?
        if (!$pasv) {
            $this->usePassive = false;
            // Pick random "low bit"
            $low = rand(39, 250);
            // Pick random "high bit"
            $high = rand(39, 250);
            // Lowest  possible port would be; 10023
            // Highest possible port would be; 64246

            $port = ($low<<8)+$high;

            $ip = null;
            socket_getpeername(socket_import_stream($this->socket), $ip);
            $ip   = str_replace('.', ',', $ip);
            $s    = $ip.','.$low.','.$high;
            $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            if (is_resource($socket)) {
                if (socket_bind($socket, '0.0.0.0', $port)) {
                    if (socket_listen($socket)) {
                        $this->data = &$socket;
                        fputs($this->socket, 'PORT '.$s."\r\n");
                        $line = fgets($this->socket, 512);
                        if (substr($line, 0, 3) == 200) {
                            return $this;
                        }
                    }
                }
            }
            throw new FtpException($line);
        }

        // Since we are here, we are suppost to create passive data connection.
        fputs($this->socket, 'PASV' ."\r\n");

        $content = [];
        do {
            $content[] = fgets($this->socket, 128);
            $array     = socket_get_status($this->socket);
        } while ($array['unread_bytes']);

        if (substr($cont = $content[count($content)-1], 0, 3) != 227) {
            throw new FtpException($content[count($content)-1]);
        }

        $pos    = strpos($cont, '(')+1;
        $pos2   = strrpos($cont, ')')-$pos;
        $string = substr($cont, $pos, $pos2);

        $array = explode(',', $string);

        // IP we are connecting to
        $ip = $array[0]. '.' .$array[1]. '.' .$array[2]. '.' .$array[3];

        // Port ( 256*lowbit + highbit
        $port = ($array[4] << 8)+$array[5];

        // Our data connection
        $iError = 0;
        $sError = '';
        $data   = fsockopen(
            $ip,
            $port,
            $iError,
            $sError,
            $this->timeout
        );

        if (is_resource($data)) {
            $this->usePassive = true;
            $this->data = &$data;
            stream_set_blocking($data, true);
            stream_set_timeout($data, $this->timeout);

            return $this;
        }

        throw new FtpException('Could not open data socket: [' . $iError . '] ' . $sError);
    }

    public function rawlist($pwd, $recursive = false)
    {
        $this->verifyConnection();

        if (!is_string($pwd)) {
            throw new InvalidArgumentException('Path must be a string.');
        }
        if (!is_resource($this->data)) {
            $this->pasv($this->usePassive);
        }
        fputs($this->socket, 'LIST '.$pwd."\r\n");

        $msg = fgets($this->socket, 512);
        if (substr($msg, 0, 3) == 425) {
            throw new FtpException($msg);
        }

        $data = &$this->data;
        if (!$this->usePassive) {
            $data = socket_accept($data);
        }

        $content = [];

        switch ($this->usePassive) {
        case true:
            while (true) {
                $string = rtrim(fgets($data, 1024));

                if ($string=='') {
                    break;
                }

                $content[] = $string;
            }

            fclose($data);
            break;

        case false:
            $string = socket_read($data, 1024, PHP_BINARY_READ);

            $content = explode("\n", $string);
            unset($content[count($content)-1]);

            socket_close($data);
            break;
        }

        $data = $this->data = null;

        fgets($this->socket, 1024);

        return $content;
    }

    public function systype()
    {
        $this->verifyConnection();

        fputs($this->socket, 'SYST'."\r\n");
        $line = fgets($this->socket, 256);

        if (substr($line, 0, 3) != 215) {
            return false;
        }

        $os = substr($line, 4, strpos($line, ' ', 4)-4);

        return $os;
    }

    public function alloc($int, &$msg = null)
    {
        $this->verifyConnection();
        if (!is_integer($int)) {
            throw new InvalidArgumentException('Argument must be of type int.');
        }

        fputs($this->socket, 'ALLO '.$int.' R '.$int."\r\n");

        $msg = rtrim(fgets($this->socket, 256));

        $code = substr($msg, 0, 3);
        if ($code == 200 || $code == 202) {
            return $this;
        }

        throw new FtpException($msg);
    }

    public function put($remote, $local, $mode = 1)
    {
        $this->verifyConnection();
        if (!is_readable($local) || !is_integer($mode)) {
            throw new FtpException('Invalid file or mode');
        }

        $types   = [
            0 => 'A',
            1 => 'I'
        ];
        $windows = [
            0 => 't',
            1 => 'b'
        ];

        /**
        * TYPE values:
        *       A ( ASCII  )
        *       I ( BINARY )
        *       E ( EBCDIC )
        *       L ( BYTE   )
        */
        if (!is_resource($this->data)) {
            $this->pasv($this->usePassive);
        }

        // Establish data connection variable
        $data = &$this->data;

        // Decide TYPE to use
        fputs($this->socket, 'TYPE '.$types[$mode]."\r\n");
        $line = fgets($this->socket, 256); // "Type set to TYPE"
        if (substr($line, 0, 3) != 200) {
            throw new FtpException($line);
        }

        fputs($this->socket, 'STOR '.$remote."\r\n");
        sleep(1);
        $line = fgets($this->socket, 256); // "Opening TYPE mode data connect."

        if (substr($line, 0, 3) != 150) {
            throw new FtpException($line);
        }

        // Creating resource to $local file
        $fp = fopen($local, 'r'. $windows[$mode]);
        if (!is_resource($fp)) {
            $fp = null;
            throw new FtpException('Could not create local resource.');
        }

        // Loop throu that file and echo it to the data socket
        $i = 0;
        switch ($this->usePassive) {
        case false:
            $data = socket_accept($data);
            while (!feof($fp)) {
                $i += socket_write($data, fread($fp, 10240), 10240);
            }
            socket_close($data);
            break;

        case true:
            while (!feof($fp)) {
                $i += fputs($data, fread($fp, 10240), 10240);
            }
            fclose($data);
            break;
        }

        $data = null;
        do {
            $line = fgets($this->socket, 256);
        } while (substr($line, 0, 4) != "226 ");

        return $this;
    }

    public function get($local, $remote, $mode = 1)
    {
        $this->verifyConnection();
        if (!is_writable(dirname($local)) || !is_integer($mode)) {
            throw new FtpException('Invalid file or mode.');
        }
        $types   = [
            0 => 'A',
            1 => 'I'
        ];
        $windows = [
            0 => 't',
            1 => 'b'
        ];

        if (!is_resource($this->data)) {
            $this->pasv($this->usePassive);
        }

        fputs($this->socket, 'TYPE '.$types[$mode]."\r\n");
        $line = fgets($this->socket, 256);
        if (substr($line, 0, 3) != 200) {
            throw new FtpException($line);
        }

        $fp = fopen($local, 'w'.$windows[$mode]);
        if (!is_resource($fp)) {
            $fp = null;
            throw new FtpException('Could not create local resource.');
        }
        fputs($this->socket, 'RETR '.$remote."\r\n");
        $line = fgets($this->socket, 256);
        if (substr($line, 0, 3) != 150) {
            throw new FtpException($line);
        }

        $data = &$this->data;
        if (!$this->usePassive) {
            $data = socket_accept($data);
        }

        $content = [];
        switch ($this->usePassive) {
        case true:
            while (!\feof($data)) {
                fputs($fp, fgets($data, 1024));
            }

            fclose($data);
            fclose($fp);
            break;

        case false:
            while ($string = socket_read($data, 1024, PHP_BINARY_READ)) {
                fputs($fp, $string);
            }
            socket_close($data);
            fclose($fp);
            break;
        }

        $data = $this->data = null;

        $line = fgets($this->socket, 256);
        if (substr($line, 0, 3) != 226) {
            throw new FtpException($line);
        }

        return $this;
    }

    public function cdup()
    {
        $this->verifyConnection();
        fputs($this->socket, 'CDUP'."\r\n");
        $line = fgets($this->socket, 256);

        if (substr($line, 0, 3) != 250) {
            throw new FtpException($line);
        }

        return $this;
    }

    public function chmod($mode, $file)
    {
        $this->verifyConnection();
        if (!is_integer($mode) || !is_string($file)) {
            throw new InvalidArgumentException('Invalid file or mode types.');
        }

        // chmod not in the standard, proftpd doesn't recognize it
        // use SITE CHMOD?
        fputs($this->socket, 'SITE CHMOD '.$mode. ' ' .$file."\r\n");
        $line = fgets($this->socket, 256);

        if (substr($line, 0, 3) == 200) {
            return $this;
        }

        throw new FtpException($line);
    }

    public function delete($path)
    {
        $this->verifyConnection();
        if (!is_string($path)) {
            throw new InvalidArgumentException('File path must be a string.');
        }

        fputs($this->socket, 'DELE '.$path."\r\n");
        $line = fgets($this->socket, 256);

        if (substr($line, 0, 3) == 250) {
            return $this;
        }

        throw new FtpException($line);
    }

    public function exec($cmd)
    {
        $this->verifyConnection();
        if (!is_string($cmd)) {
            throw new InvalidArgumentException('Command must be a string.');
        }

        // Command not defined in the standart
        // proftpd doesn't recognize SITE EXEC (only help,chgrp,chmod and ratio)
        fputs($this->socket, 'SITE EXEC '.$cmd."\r\n");
        $line = fgets($this->socket, 256);

        if (substr($line, 0, 3) == 200) {
            return $this;
        }

        throw new FtpException($line);
    }

    protected function verifyConnection()
    {
        if (!is_resource($this->socket)) {
            throw new FtpException('Invalid state: disconnected.');
        }

        return true;
    }
}
