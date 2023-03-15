# vulcat

[![python](https://img.shields.io/badge/Python-3-blue?logo=python)](https://shields.io/)
[![version](https://img.shields.io/badge/Version-2.0.0-blue)](https://shields.io/)
[![license](https://img.shields.io/badge/LICENSE-GPL-yellow)](https://shields.io/)
[![stars](https://img.shields.io/github/stars/CLincat/vulcat?color=red)](https://shields.io/)
[![forks](https://img.shields.io/github/forks/CLincat/vulcat?color=red)](https://shields.io/)

**[English version(英文版本)](/README.en-us.md)**

[官方文档](https://clincat.github.io/vulcat-docs/)
(本工具随缘更新)<br>
除了代码写得有亿点点烂, BUG有亿点点多, 有亿点点不好用, 等亿点点小问题以外，还是阔以的......吧

* vulcat是一个用于扫描web端漏洞的工具，支持WAF检测、指纹识别、POC扫描、自定义POC等功能
* 当vulcat发现问题时会输出漏洞信息、漏洞利用的Request数据包等，使用者可以根据提示对漏洞进行手工验证、深入利用等
* 支持.txt .json .html报告的导出
* 如果有什么想法、建议或者遇到了BUG, 都可以issues

## 官方文档

[官方文档](https://clincat.github.io/vulcat-docs/)

## 行为规范和免责声明
* **在使用本工具前, 请确保您的行为符合当地法律法规, 并且已经取得了相关授权。**

* **本工具仅面向拥有合法授权的企业和个人等, 意在加强网络空间安全。**

* **如果您在使用本工具的过程中存在任何非法行为, 或造成了任何严重后果, 您需自行承担相应责任, 我们将不承担任何法律及连带责任。**

## 安装 && 使用
工具基于python3开发, 推荐使用python3.8及以上版本

* Git: `git clone https://github.com/CLincat/vulcat.git`
* Zip: [点我](https://github.com/CLincat/vulcat/archive/refs/heads/main.zip)

```
git clone https://github.com/CLincat/vulcat.git
cd vulcat
pip3 install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple
python3 vulcat.py -h
```
```
Usage:
使用本工具, 代表您同意"vulcat/README.md"中的"行为规范和免责声明"; 如果您不同意, 请勿使用本工具


Usage: python3 vulcat.py <options>
Examples:
python3 vulcat.py -h
python3 vulcat.py --list
python3 vulcat.py -u https://www.example.com/
python3 vulcat.py -f url.txt -o html
python3 vulcat.py -u https://www.example.com/ -v httpd --log 3
python3 vulcat.py -u https://www.example.com/ -v cnvd-2018-24942 --shell
```

## 攻击载荷列表
<details>
<summary><strong>以下是vulcat拥有的攻击载荷: [点击展开]</strong></summary>

```
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| Payloads                                                 | Sh  | Description                                                          |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| 74cms-v5.0.1-sqlinject                                   |  -  | 74cms v5.0.1 前台AjaxPersonalController.class.php存在SQL注入         |
| 74cms-v6.0.4-xss                                         |  -  | 74cms v6.0.4 帮助中心搜索框XSS                                       |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| alibaba-druid-unauth                                     |  -  | 阿里巴巴Druid未授权访问                                              |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| alibaba-nacos-cve-2021-29441-unauth                      |  -  | 阿里巴巴Nacos未授权访问                                              |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| apache-airflow-cve-2020-17526-unauth                     |  -  | Airflow身份验证绕过                                                  |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| apache-apisix-cve-2020-13945-unauth                      |  -  | Apache APISIX默认密钥                                                |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| apache-druid-cve-2021-25646-rce                          |  Y  | Apache Druid 远程代码执行                                            |
| apache-druid-cve-2021-36749-fileread                     |  Y  | Apache Druid 任意文件读取                                            |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| apache-flink-cve-2020-17519-fileread                     |  Y  | Flink目录遍历                                                        |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| apache-hadoop-unauth                                     |  -  | Hadoop YARN ResourceManager 未授权访问                               |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| apache-httpd-cve-2021-40438-ssrf                         |  -  | Apache HTTP Server 2.4.48 mod_proxy SSRF                             |
| apache-httpd-cve-2021-41773-rce-fileread                 |  Y  | Apache HTTP Server 2.4.49 路径遍历                                   |
| apache-httpd-cve-2021-42013-rce-fileread                 |  Y  | Apache HTTP Server 2.4.50 路径遍历                                   |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| apache-skywalking-cve-2020-9483-sqlinject                |  -  | SkyWalking SQL注入                                                   |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| apache-solr-cve-2017-12629-rce                           |  -  | Solr 远程命令执行                                                    |
| apache-solr-cve-2019-17558-rce                           |  Y  | Solr Velocity 注入远程命令执行                                       |
| apache-solr-cve-2021-27905-ssrf-fileread                 |  Y  | Solr SSRF/任意文件读取                                               |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| apache-tomcat-cve-2017-12615-fileupload                  |  -  | PUT方法任意文件写入                                                  |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| apache-unomi-cve-2020-13942-rce                          |  Y  | Apache Unomi远程表达式代码执行                                       |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| appweb-cve-2018-8715-unauth                              |  -  | AppWeb身份认证绕过                                                   |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| atlassian-confluence-cve-2015-8399-fileread-fileinclude  |  Y  | Confluence任意文件包含                                               |
| atlassian-confluence-cve-2019-3396-fileread              |  Y  | Confluence路径遍历和命令执行                                         |
| atlassian-confluence-cve-2021-26084-rce                  |  Y  | Confluence Webwork Pre-Auth OGNL表达式命令注入                       |
| atlassian-confluence-cve-2022-26134-rce                  |  Y  | Confluence远程代码执行                                               |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| cisco-cve-2020-3580-xss                                  |  -  | 思科ASA/FTD XSS跨站脚本攻击                                          |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| discuz-wooyun-2010-080723-rce                            |  Y  | 全局变量防御绕过RCE                                                  |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| django-cve-2017-12794-xss                                |  -  | debug page XSS跨站脚本攻击                                           |
| django-cve-2018-14574-redirect                           |  -  | CommonMiddleware url重定向                                           |
| django-cve-2019-14234-sqlinject                          |  -  | JSONfield SQL注入                                                    |
| django-cve-2020-9402-sqlinject                           |  -  | GIS SQL注入                                                          |
| django-cve-2021-35042-sqlinject                          |  -  | QuerySet.order_by SQL注入                                            |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| drupal-cve-2014-3704-sqlinject                           |  -  | Drupal < 7.32 Drupalgeddon SQL 注入                                  |
| drupal-cve-2017-6920-rce                                 |  -  | Drupal Core 8 PECL YAML 反序列化代码执行                             |
| drupal-cve-2018-7600-rce                                 |  Y  | Drupal Drupalgeddon 2 远程代码执行                                   |
| drupal-cve-2018-7602-rce                                 |  -  | Drupal 远程代码执行                                                  |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| elasticsearch-cve-2014-3120-rce                          |  Y  | ElasticSearch命令执行                                                |
| elasticsearch-cve-2015-1427-rce                          |  Y  | ElasticSearch Groovy 沙盒绕过&&代码执行                              |
| elasticsearch-cve-2015-3337-fileread                     |  Y  | ElasticSearch 目录穿越                                               |
| elasticsearch-cve-2015-5531-fileread                     |  Y  | ElasticSearch 目录穿越                                               |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| f5bigip-cve-2020-5902-rce-fileread                       |  -  | BIG-IP远程代码执行                                                   |
| f5bigip-cve-2022-1388-unauth-rce                         |  Y  | BIG-IP身份认证绕过RCE                                                |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| fastjson-cnvd-2017-02833-rce                             |  Y  | Fastjson <= 1.2.24 反序列化                                          |
| fastjson-cnvd-2019-22238-rce                             |  Y  | Fastjson <= 1.2.47 反序列化                                          |
| fastjson-v1.2.62-rce                                     |  Y  | Fastjson <= 1.2.62 反序列化                                          |
| fastjson-v1.2.66-rce                                     |  Y  | Fastjson <= 1.2.66 反序列化                                          |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| gitea-unauth-fileread-rce                                |  -  | Gitea 1.4.0 未授权访问                                               |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| gitlab-cve-2021-22205-rce.py                             |  -  | GitLab Pre-Auth 远程命令执行                                         |
| gitlab-cve-2021-22214-ssrf                               |  Y  | Gitlab CI Lint API未授权 SSRF                                        |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| gocd-cve-2021-43287-fileread                             |  Y  | GoCD Business Continuity 任意文件读取                                |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| grafana-cve-2021-43798-fileread                          |  Y  | Grafana 8.x 插件模块路径遍历                                         |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| influxdb-unauth                                          |  -  | influxdb 未授权访问                                                  |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| jboss-unauth                                             |  -  | JBoss 未授权访问                                                     |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| jenkins-cve-2018-1000861-rce                             |  Y  | jenkins 远程命令执行                                                 |
| jenkins-unauth                                           |  Y  | Jenkins 未授权访问                                                   |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| jetty-cve-2021-28164-dsinfo                              |  -  | jetty 模糊路径信息泄露                                               |
| jetty-cve-2021-28169-dsinfo                              |  -  | jetty Utility Servlets ConcatServlet 双重解码信息泄露                |
| jetty-cve-2021-34429-dsinfo                              |  -  | jetty 模糊路径信息泄露                                               |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| joomla-cve-2017-8917-sqlinject                           |  -  | Joomla3.7 Core com_fields组件SQL注入                                 |
| joomla-cve-2023-23752-unauth                             |  -  | Joomla 未授权访问                                                    |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| jupyter-unauth                                           |  -  | Jupyter 未授权访问                                                   |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| keycloak-cve-2020-10770-ssrf                             |  -  | 使用request_uri调用未经验证的URL                                     |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| landray-oa-cnvd-2021-28277-ssrf-fileread                 |  Y  | 蓝凌OA 任意文件读取/SSRF                                             |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| minihttpd-cve-2018-18778-fileread                        |  -  | mini_httpd 任意文件读取                                              |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| mongoexpress-cve-2019-10758-rce                          |  Y  | 未授权远程代码执行                                                   |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| nexus-cve-2019-5475-rce                                  |  Y  | 2.x yum插件 远程命令执行                                             |
| nexus-cve-2019-7238-rce                                  |  Y  | 3.x 远程命令执行                                                     |
| nexus-cve-2019-15588-rce                                 |  Y  | 2019-5475的绕过                                                      |
| nexus-cve-2020-10199-rce                                 |  Y  | 3.x 远程命令执行                                                     |
| nexus-cve-2020-10204-rce                                 |  Y  | 3.x 远程命令执行                                                     |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| nodejs-cve-2017-14849-fileread                           |  Y  | Node.js目录穿越                                                      |
| nodejs-cve-2021-21315-rce                                |  Y  | Node.js命令执行                                                      |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| nodered-cve-2021-3223-fileread                           |  Y  | Node-RED 任意文件读取                                                |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| phpmyadmin-cve-2018-12613-fileinclude-fileread           |  -  | phpMyadmin Scripts/setup.php 反序列化                                |
| phpmyadmin-wooyun-2016-199433-unserialize                |  Y  | phpMyadmin 4.8.1 远程文件包含                                        |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| phpunit-cve-2017-9841-rce                                |  Y  | PHPUnit 远程代码执行                                                 |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| ruby-on-rails-cve-2018-3760-fileread                     |  Y  | Ruby on Rails 路径遍历                                               |
| ruby-on-rails-cve-2019-5418-fileread                     |  Y  | Ruby on Rails 任意文件读取                                           |
| ruby-on-rails-cve-2020-8163-rce                          |  -  | Ruby on Rails 命令执行                                               |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| showdoc-cnvd-2020-26585-fileupload                       |  -  | ShowDoc 任意文件上传                                                 |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| spring-security-oauth-cve-2016-4977-rce                  |  -  | Spring Security OAuth2 远程命令执行                                  |
| spring-data-rest-cve-2017-8046-rce                       |  -  | Spring Data Rest 远程命令执行                                        |
| spring-data-commons-cve-2018-1273-rce                    |  Y  | Spring Data Commons 远程命令执行                                     |
| spring-cloud-config-cve-2020-5410-fileread               |  Y  | Spring Cloud目录遍历                                                 |
| spring-boot-cve-2021-21234-fileread                      |  Y  | Spring Boot目录遍历                                                  |
| spring-cloud-gateway-cve-2022-22947-rce                  |  -  | Spring Cloud Gateway SpEl远程代码执行                                |
| spring-cloud-function-cve-2022-22963-rce                 |  Y  | Spring Cloud Function SpEL远程代码执行                               |
| spring-cve-2022-22965-rce                                |  -  | Spring Framework远程代码执行                                         |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| supervisor-cve-2017-11610-rce                            |  -  | Supervisor 远程命令执行                                              |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| thinkphp-cve-2018-1002015-rce                            |  Y  | ThinkPHP5.x 远程代码执行                                             |
| thinkphp-cnvd-2018-24942-rce                             |  Y  | 未开启强制路由导致RCE                                                |
| thinkphp-cnnvd-201901-445-rce                            |  Y  | 核心类Request远程代码执行                                            |
| thinkphp-cnvd-2022-86535-rce                             |  -  | ThinkPHP 多语言模块命令执行                                          |
| thinkphp-2.x-rce                                         |  -  | ThinkPHP2.x 远程代码执行                                             |
| thinkphp-5-ids-sqlinject                                 |  -  | ThinkPHP5 ids参数SQL注入                                             |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| ueditor-ssrf                                             |  -  | Ueditor编辑器SSRF                                                    |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| uwsgiphp-cve-2018-7490-fileread                          |  Y  | uWSGI-PHP目录穿越                                                    |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| vmware-vcenter-2020-10-fileread                          |  Y  | 2020年 VMware vCenter 6.5任意文件读取                                |
| vmware-vcenter-cve-2021-21972-fileupload-rce             |  -  | VMware vSphere Client 远程代码执行                                   |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| oracle-weblogic-cve-2014-4210-ssrf                       |  -  | Weblogic 服务端请求伪造                                              |
| oracle-weblogic-cve-2017-10271-unserialize               |  -  | Weblogic XMLDecoder反序列化                                          |
| oracle-weblogic-cve-2019-2725-unserialize                |  -  | Weblogic wls9_async反序列化                                          |
| oracle-weblogic-cve-2020-14750-bypass                    |  -  | Weblogic 权限验证绕过                                                |
| oracle-weblogic-cve-2020-14882-rce-unauth                |  Y  | Weblogic 未授权命令执行                                              |
| oracle-weblogic-cve-2021-2109-rce                        |  -  | Weblogic LDAP 远程代码执行                                           |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| webmin-cve-2019-15107-rce                                |  Y  | Webmin Pre-Auth 远程代码执行                                         |
| webmin-cve-2019-15642-rce                                |  Y  | Webmin 远程代码执行                                                  |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| yonyou-grp-u8-cnnvd-201610-923-sqlinject                 |  -  | 用友GRP-U8 Proxy SQL注入                                             |
| yonyou-nc-cnvd-2021-30167-rce                            |  Y  | 用友NC BeanShell远程命令执行                                         |
| yonyou-erp-nc-ncfindweb-fileread                         |  -  | 用友ERP-NC NCFindWeb目录遍历                                         |
| yonyou-u8-oa-getsession-dsinfo                           |  -  | 用友U8 OA getSessionList.jsp 敏感信息泄漏                            |
| yonyou-u8-oa-test.jsp-sqlinject                          |  -  | 用友U8 OA test.jsp SQL注入                                           |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
| zabbix-cve-2016-10134-sqlinject                          |  -  | latest.php或jsrpc.php存在sql注入                                     |
+----------------------------------------------------------+-----+----------------------------------------------------------------------+
vulcat-2.0.0/2023.03.15
112/Poc
55/Shell
```
</details>

## 感谢
* [vulmap](https://github.com/zhzyker/vulmap)
* [sqlmap](https://github.com/sqlmapproject/sqlmap)
* [dirsearch](https://github.com/maurosoria/dirsearch)
* [HackRequests](https://github.com/boy-hack/hack-requests)
* [vulhub](https://github.com/vulhub/vulhub)
* [vulfocus](https://github.com/fofapro/vulfocus)
* [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap/)
* [Xray](github.com/chaitin/xray)

## Star History
[![Star History Chart](https://api.star-history.com/svg?repos=CLincat/vulcat&type=Timeline)](https://star-history.com/#Ashutosh00710/github-readme-activity-graph&Timeline)