# fxtunnel
[![MIT License]([https://img.shields.io/github/license/xiaocong/uiautomator.svg](http://opensource.org/licenses/MIT)

Two-way port mapping tool, supports TCP and UDP, Secure connection using SSL.

## Introduce
* Supports port mapping for TCP and UDP protocols
* Cross-platform, Windows, Linux, MacOS
* Using select asynchronous events is not suitable for large concurrency scenarios
* Openssl secure tunnel

## Architecture
* Agent is responsible for port listening
* Connector is responsible for connecting to the destination port
![architecture](https://github.com/zebecool/fxtunnel/blob/main/architecture.jpg)

## Compile and Install

1.  服务启动  python main.py start
2.  默认端口 18997
2.  H5页面访问地址  http://127.0.0.1:18977/static/login.html
3.  默认用户 11111111111 密码 2222  具备管理权限，可以编辑考试信息，发布新的考试
4.  系统具备较完整的功能，完全匿名进行学生的成绩采集，对管理方也是匿名的, 可以完全避免考试成绩泄露
5.  使用者使用任意无特征的用户名和考试登记码进行考试成绩登记，然后查看总分及各科成绩的班级汇总统计分析



#### PPForward

![截图](https://gitee.com/zebecool/xueqing/raw/master/screenshot.png)
