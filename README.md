# fxtunnel
[![MIT License](https://img.shields.io/github/license/xiaocong/uiautomator.svg)](http://opensource.org/licenses/MIT)

Two-way port mapping tool, supports TCP and UDP, Secure connection using SSL.

## Introduce
* Supports port mapping for TCP and UDP protocols 
* Cross-platform, Windows, Linux, MacOS 
* Using select asynchronous events is not suitable for large concurrency scenarios 
* Openssl secure tunnel 
* Protocol parameter 
  - `tcp_sa`  TCP protocol.  Listening mapped port on the server, client is responsible for connecting to the destination port.
  - `tcp_sc`  TCP protocol.  Server is responsible for connecting to the destination port, Listening mapped port on the client.
  - `udp_sa`  UDP protocol.  Listening mapped port on the server, client is responsible for connecting to the destination port.
  - `udp_sc`  UDP protocol.  Server is responsible for connecting to the destination port, Listening mapped port on the client.

## Architecture
* Agent is responsible for port listening
* Connector is responsible for connecting to the destination port
![architecture](https://github.com/zebecool/fxtunnel/blob/main/architecture.jpg)

## Configuration File
* The server and client have the same code, and the running role is determined based on the "mode" field in the configuration file.
* The server needs to configure certificate files `server.crt` and `server.key`.
    ```
	openssl genrsa -out server.key 1024
	```
	```
	openssl req -new -x509 -days 3650 -key server.key -out server.crt -subj "/C=CN/ST=xxname/L=xxname/O=xxname/OU=xxname/CN=xxdomain"
	```
* Server side (fxtunnel.conf) 
    ```
    {
        "log_level": "debug",
        "mode": "server",
        "listen_port": 7838,
        "links": [
            {
                "authkey": "client-1---xxxxxx",
                "services": [
                    {
                        "name": "Remote desktop",
                        "protocol": "tcp_sa",
                        "mapped_port": 13389,
                        "connect_addr": "127.0.0.1",
                        "connect_port": 3389
                    },
                    {
                        "name": "https service",
                        "protocol": "tcp_sc",
                        "mapped_port": 10443,
                        "connect_addr": "www.xxxxxx.com",
                        "connect_port": 443
                    }
                ]
            },
            {
                "authkey": "client-2---xxxxxx",
                "services": [
                    {
                        "name": "udp test service",
                        "protocol": "udp_sa",
                        "mapped_port": 28001,
                        "connect_addr": "192.168.0.10",
                        "connect_port": 8001
                    }
                ]
            }
        ]
    }
    ```

* Client side (fxtunnel.conf) 
    ```
    {
        "log_level": "info",
        "mode": "client",
        "server_addr": "10.101.102.103",
        "server_port": 7838,
        "authkey": "client-1---xxxxxx"
    }
    ```

## Compile and Install

You need:
* Openssl development headers and library
* CMake build system

Compiling is straight forward with cmake, For e.g., on Linux/OS X/FreeBSD:
```
$ git clone https://github.com/zebecool/fxtunnel.git
$ cd fxtunnel
$ mkdir build && cd build
$ cmake ../
$ make install
```


## PPForward
![PPForward](http://ppforward.com/assets/images/logo-dark.png) 






