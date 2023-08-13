# 态势感知系统

## 项目介绍

历经15天的紧张开发，陈志鹏和陈俊哲联手开发了此态势感知系统。本系统已经实现了**以下功能**：

1.单文件部署，只需要上传可执行文件执行即可完成部署，不需要任何额外依赖，方便快捷。

2.自动备份网站源码、一键扫描恶意文件。并且拥有文件监控功能，当文件生成时自动检测是否恶意文件，检测到恶意内容时自动备份样本后删除，自动对抗各种可能的木马和后门。

3.提供webUI界面，所有操作都可在web界面完成。

4.数据包拦截监控，拦截危险操作并记录数据包。

5.IP封堵，在webUI界面便捷的封禁或解封ip。

6.为自己的势态感知系统做好身份验证，防止其他人访问.

7.利用数据库存储对应的数据 。



## 环境依赖

硬性需要是Linux操作系统

测试部署环境是：

1. Apache 2.4.46

2. MariaDB 10.5.9

3. CentOS 7.8 64bit

## 目录结构描述

├── ReadMe.md                                             //帮助文档

├──readrock                                                   //项目代码文件夹

​       ├── main.go                                            //项目主函数

​       ├──go.mod                                             //模块定义文件

​               └── go.sum                                    //模块校验文件

​       ├──apache                                             //apache包

​               └── apache.go                              //apache相关函数

​       ├──backup                                            //backup包

​               └── backup.go                             //网站源码备份

​       ├──changeport                                   //changeport包

​               └── changeport.go                    //apache端口更改

​       ├──checkrequest                               //checkrequest包

​               ├──xml                                        //xml文件

​                      └── default_filter.xml        //筛选器

​               └── checkrequest.go               //攻击检查

​       ├──ddosprotection                         //ddosprotection包

​               └── ddosprotection.go          //中间件保护

​       ├──deepscan                                  //deepscan包

​               └── deepscan.go                   //深度扫描

​       ├──filedelet                                    //filedelet包

​               └── filedelet.go                     //文件删除

​       ├──filemonitor                              //filemonitor包

​               └── filemonitor.go               //文件监控

​       ├──login                                        //login包

​               └── login.go                         //登录

​       ├──maliciousfiles                       //maliciousfiles包

​               └── maliciousfiles.go        //检测恶意文件

​       ├──sqlserve                                //sqlserve包

​               └── sqlserve.go                 //数据库相关函数

​       ├──WebUI                                  //WebUI包

​               ├── information.html      //数据包页面

​               ├── initialize.html            //初始化页面

​               ├── ip.html                       //ip封禁页面

​               ├── login.html                 //登录页面

​               ├── main.html                //文件监控及扫描页面

​               └── 27.jpg                       //背景图片

├──go_build_redrock_linux        //Linux可执行文件

## 使用说明

打开服务器（或虚拟机），切换至root用户，在服务器（或虚拟机）里上传go_build_redrock_linux文件，然后使用./命令运行这个文件即可启动本系统。打开浏览器输入xxx:7777/login（xxx为服务器或虚拟机的ip）即可来到登录页面

![](https://smallblack2022.oss-cn-hangzhou.aliyuncs.com/img/202307221952025.png)

![](https://smallblack2022.oss-cn-hangzhou.aliyuncs.com/img/202307221952409.png)

然后默认用户名和密码为redrock，输入账号密码，验证码进行登录来到初始化页面

![](https://smallblack2022.oss-cn-hangzhou.aliyuncs.com/img/202307221953580.png)

根据提示输入对应信息，MySQL地址一般默认为127.0.0.1，端口为3306，数据库必须为已有数据库建议自己使用前自建一个为空的数据库，root密码取决于自己。然后网站根目录，apache（或ngnix）配置文件为自己服务器（或虚拟机）的自有地址，端口建议使用80，用户名及登录密码取决于自己，然后点击初始化来到文件监控及扫描页面

![](https://smallblack2022.oss-cn-hangzhou.aliyuncs.com/img/202307221953454.png)

在此页面可以进行使用文件监控功能，当文件生成时自动检测是否恶意文件，检测到恶意内容时自动备份样本后删除，自动对抗各种可能的木马和后门。

点击跳转到/IP面板

![](https://smallblack2022.oss-cn-hangzhou.aliyuncs.com/img/202307221953221.png)

在这里可以添加禁止的IP或者删除被禁的IP，对应被IP封禁的列表会出现在下面

点击跳转来到/流量监控面板

这里会显示各个数据包的信息，点击对应列，会在右侧显示出单个数据包的完整信息

![](https://smallblack2022.oss-cn-hangzhou.aliyuncs.com/img/202307221953517.png)

以上便是此态势感知系统的完整功能

## 防护类特别说明

本态势感知系统采用了多种防护，励志做到能防尽防

首先是**文件扫描部分**

我们共使用了两种方式对文件进行扫描，分别是通过字典进行匹配扫描和调用微步云沙箱对文件进行扫描，先使用字典批量扫描网站内文件，检测是否有特殊文件名或文件类型，然后再调用微步云沙箱检测文件内容，最后通过微步云沙箱的反馈我们对文件进行评级，自动删除恶意文件和疑似文件，并将这些文件备份到/var/www/backup。

注意：API Key（需要配置自己的key，代码中配置的是我们自己的）

91b69f003a22496b90dad2b82661e42d15cf40c47f6447b68af8b24feaf03d32

参考：字典（https://github.com/TgeaUs/Weak-password/blob/master/Backstage/shell.txt）

​           微步云沙箱（https://s.threatbook.com/）

![](https://smallblack2022.oss-cn-hangzhou.aliyuncs.com/img/202307221955865.png)



![](https://smallblack2022.oss-cn-hangzhou.aliyuncs.com/img/202307221955324.png)

然后是**数据包部分**

我们共采用了三种方式进行防护，首先是中间件的防ddos，然后是我们自己去写的一个字典进行的总结的匹配，最后是一个正则匹配。

一，中间件的防ddos，当用户连续访问超20次，IP就会被判定为恶意请求，从而禁止访问，IP进入IP封禁的数据库，防止过大的流量冲击服务器

![](https://smallblack2022.oss-cn-hangzhou.aliyuncs.com/img/202307221955051.png)

二，字典匹配，因为这个字典非常大，所以我们对字典进行了总结，只要数据包含有字典中的特征量就会立即终止访问，IP进入IP封禁的数据库。在这里我们对sql，xss，ssrf等进行了防护，针对危险协议，url，参数，路径进行了特定的防护。

![](https://smallblack2022.oss-cn-hangzhou.aliyuncs.com/img/202307221955748.png)

三，正则匹配，我们通过文件对访问数据包进行了过滤，如果请求匹配了某个过滤器的规则，则返回请求被过滤掉，否则，表示请求通过了过滤器检查，允许访问。这里通过 default_filter.xml这个文件进行正则匹配。

![](https://smallblack2022.oss-cn-hangzhou.aliyuncs.com/img/202307221956541.png)

以上就是安全防护的总结。