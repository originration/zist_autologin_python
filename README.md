# zist_autologin_python
# 中原科技学院许昌校区校园网自动登录

## 原理解析

由于所有网页认证都是用的portal请求，原理就是通过get请求给服务器发送设备信息然后进行验证。所以可以通过python向服务器发送请求

![](file:///Users/cxk/Desktop/截屏2025-11-02%2001.05.03.png?msec=1762023641081)

通过抓包得知发送的请求的url如下：http://**172.22.5.2:801**/eportal/portal/login?callback=dr1003&login_method=1&user_account=%2C1%2C**24330125414**%40**cucc**&user_password=**123456**&wlan_user_ip=**10.11.34.50**&wlan_user_ipv6=&wlan_user_mac=000000000000&wlan_ac_ip=&wlan_ac_name=&jsVersion=4.2&terminal_type=2&lang=zh-cn&v=8174&lang=zh

字符含义如下：

| 172.22.5.2:801 | 认证服务器的地址和端口 |
| --- | --- |
| user_account=%2C1%2C**24330125414**% | 账号  |
| cucc | 运营商代码 |
| user_password | 账号密码 |
| wlan_user_ip | 终端的ip地址 |

如果成功则会返回200状态码
