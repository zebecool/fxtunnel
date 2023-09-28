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
* Server side
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

* Client side
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
1.  服务启动  python main.py start
2.  默认端口 18997
2.  H5页面访问地址  http://127.0.0.1:18977/static/login.html
3.  默认用户 11111111111 密码 2222  具备管理权限，可以编辑考试信息，发布新的考试
4.  系统具备较完整的功能，完全匿名进行学生的成绩采集，对管理方也是匿名的, 可以完全避免考试成绩泄露
5.  使用者使用任意无特征的用户名和考试登记码进行考试成绩登记，然后查看总分及各科成绩的班级汇总统计分析


## PPForward
![PPForward](http://ppforward.com/assets/images/logo-dark.png) 
* come soon.
* come soon.
* come soon.


