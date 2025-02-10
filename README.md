# RevShellGen
Yet another reverse shell generator for the CLI

About 76 shells included. Most are either publically available like from pentestmonkey or modified from their publically available form. A few are customized to work on all OS dynamically.

Usage:
```
python3 revshellgen.py -p (PORT) -i (IPADDRESS) -t (TYPE aka Programming Language)
```
or
```
python3 revshellgen.py -l
```
Current shells (output of "-l":
```
[+] Available Shell Types:

Awk:
  - awk-linux-oneline (linux-oneline)

Bash:
  - bash-tcp-1-linux-oneline (tcp-1-linux-oneline)
  - bash-tcp-2-lunix-oneline (tcp-2-lunix-oneline)
  - bash-tcp-3-linux-oneline (tcp-3-linux-oneline)
  - bash-tcp-4-linux-oneline (tcp-4-linux-oneline)
  - bash-udp-linux-oneline (udp-linux-oneline)

Busybox:
  - busybox-linux-nc-online (linux-nc-online)

C:
  - c-reverse-shell-c-code-linux.txt (reverse-shell--ode-linux.txt)
  - c-reverse-shell-winsock-windows.txt (reverse-shell-winsok-windows.txt)

Crystal:
  - crystal-reverse-shell-linux.txt (reverse-shell-linux.txt)
  - crystal-reverse-shell-windows.txt (reverse-shell-windows.txt)

Csharp:
  - csharp-reverse-osx-1.txt (reverse-osx-1.txt)
  - csharp-reverse-osx-2.txt (reverse-osx-2.txt)

Curl:
  - curl-linux-oneline (linux-oneline)

Dart:
  - dart-reverse-shell-linux.txt (reverse-shell-linux.txt)
  - dart-reverse-shell-windows.txt (reverse-shell-windows.txt)

Go:
  - go-reverse-shell-linux-oneline (reverse-shell-linux-oneline)
  - go-reverse-shell-linux.txt (reverse-shell-linux.txt)
  - go-reverse-shell-windows.txt (reverse-shell-windows.txt)

Groovy:
  - groovy-reverse-shell-osx.txt (reverse-shell-osx.txt)

Haskell:
  - haskell-nc-linux.txt (nc-linux.txt)
  - haskell-nc-windows.txt (nc-windows.txt)

Java:
  - java-process-builder-linux.txt (process-builder-linux.txt)
  - java-reverse-shell-windows.txt (reverse-shell-windows.txt)
  - java-rmi-reverse-shell-windows.txt (rmi-reverse-shell-windows.txt)
  - java-runtime-exec-linux.txt (runtime-exec-linux.txt)

Jsp:
  - jsp-web-shell-osx -1.txt (web-shell-osx -1.txt)
  - jsp-web-shell-osx-2.txt (web-shell-osx-2.txt)
  - jsp-web-shell-osx-3.txt (web-shell-osx-3.txt)

Lua:
  - lua-exec-linux-oneline (exec-linux-oneline)
  - lua-reverse-shell-linux.txt (reverse-shell-linux.txt)
  - lua-reverse-shell-windows.txt (reverse-shell-windows.txt)

Nc:
  - nc-bash--linux-oneline (bash--linux-oneline)
  - nc-c-linux-oneline (c-linux-oneline)
  - nc-c-windows-oneline (c-windows-oneline)
  - nc-e-windows-oneline (e-windows-oneline)
  - nc-mkfifo-linux-oneline (mkfifo-linux-oneline)
  - nc-mknod-linux-oneline (mknod-linux-oneline)
  - nc-udp-linux-oneline (udp-linux-oneline)

Nodejs:
  - nodejs-reverse-shell-osx.txt (reverse-shell-osx.txt)

Openssl:
  - openssl-linux-oneline (linux-oneline)

Perl:
  - perl-full-osx.txt (full-osx.txt)
  - perl-io-linux-oneline (io-linux-oneline)
  - perl-pentestmonkey-linux (pentestmonkey-linux)
  - perl-tcp-linux-oneline (tcp-linux-oneline)

Php:
  - php-backticks-osx-oneline (backticks-osx-oneline)
  - php-exec-osx-oneline (exec-osx-oneline)
  - php-ivan-sincek-reverse-shell-osx (ivan-sincek-reverse-shell-osx)
  - php-modified-pentestmonkey-osx.txt (modified-pentestmonkey-osx.txt)
  - php-proc_open-osx-oneline (proc_open-osx-oneline)
  - php-system-osx-oneline (system-osx-oneline)
  - php-web-shell-osx-1 (web-shell-osx-1)
  - php-web-shell-osx-2 (web-shell-osx-2)

Powershell:
  - powershell-windows-basic-tcp.txt (windows-basic-tcp.txt)
  - powershell-windows-conpty-oneline (windows-conpty-oneline)
  - powershell-windows-hidden.txt (windows-hidden.txt)
  - powershell-windows-ssl-encrypted.txt (windows-ssl-encrypted.txt)
  - powershell-windows-tcpclient.txt (windows-tcpclient.txt)

Python:
  - python-linux-oneline.txt (linux-oneline.txt)
  - python-pty-linux-oneline.txt (pty-linux-oneline.txt)
  - python-threaded-cmd-osx.txt (threaded-cmd-osx.txt)

Ruby:
  - ruby-advanced-reverse-osx.txt (advanced-reverse-osx.txt)
  - ruby-rsocket-linux-oneline (rsocket-linux-oneline)
  - ruby-rsocket-windows-oneline (rsocket-windows-oneline)
  - ruby-tcp-linux-oneline (tcp-linux-oneline)
  - ruby-tcp-windows-oneline (tcp-windows-oneline)

Rust:
  - rust-osx.txt (osx.txt)

Rustcat:
  - rustcat-linux-oneline (linux-oneline)
  - rustcat-windows-oneline (windows-oneline)

Socat:
  - socat-linux-exec-oneline (linux-exec-oneline)
  - socat-linux-tcp-pty-oneline.txt (linux-tcp-pty-oneline.txt)

Sqlite:
  - sqlite-shell-linux-oneline (shell-linux-oneline)

Tclsh:
  - tclsh-linux-oneline (linux-oneline)
  - tclsh-reverse-osx.txt (reverse-osx.txt)

Telnet:
  - telnet-reverse-linux-oneline (reverse-linux-oneline)

V:
  - v-nc-reverse-osx.txt (nc-reerse-osx.txt)
  - v-nc-reverse-shell-linux-oneline (nc-reerse-shell-linux-oneline)

Zsh:
  - zsh-reverse-shell-linux-oneline (reverse-shell-linux-oneline)
```
This was made with the goal of adding it to a different project of mine (https://github.com/V1236/Remy-Red-Team-Assistant) but its useful on its own without needing any changes.
