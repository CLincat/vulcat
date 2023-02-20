# vulcat

[![python](https://img.shields.io/badge/Python-3-blue?logo=python)](https://shields.io/)
[![version](https://img.shields.io/badge/Version-1.1.9-blue)](https://shields.io/)
[![license](https://img.shields.io/badge/LICENSE-GPL-yellow)](https://shields.io/)
[![stars](https://img.shields.io/github/stars/CLincat/vulcat?color=red)](https://shields.io/)
[![forks](https://img.shields.io/github/forks/CLincat/vulcat?color=red)](https://shields.io/)

**[English version(英文版本)](/README.en-us.md)**

(每月更新)<br>
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
python3 vulcat.py -u https://www.example.com/ -o html
python3 vulcat.py -u https://www.example.com/ -a httpd --log 3
python3 vulcat.py -u https://www.example.com/ -a thinkphp -v cnvd-2018-24942
python3 vulcat.py -f url.txt -t 10
```

## 漏洞列表
<details>
<summary><strong>目前支持检测的漏洞: [点击展开]</strong></summary>

```
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Target               | Vuln id            | Vuln Type    | Sh  | Description                                                          |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Alibaba Druid        | (None)             | unAuth       |  -  | 阿里巴巴Druid未授权访问                                              |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Alibaba Nacos        | CVE-2021-29441     | unAuth       |  -  | 阿里巴巴Nacos未授权访问                                              |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Apache Airflow       | CVE-2020-17526     | unAuth       |  -  | Airflow身份验证绕过                                                  |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Apache APISIX        | CVE-2020-13945     | unAuth       |  -  | Apache APISIX默认密钥                                                |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Apache Druid         | CVE-2021-25646     | RCE          |  Y  | Apache Druid 远程代码执行                                            |
| Apache Druid         | CVE-2021-36749     | FileRead     |  Y  | Apache Druid 任意文件读取                                            |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Apache Flink         | CVE-2020-17519     | FileRead     |  Y  | Flink目录遍历                                                        |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Apache Hadoop        | (None)             | unAuth       |  -  | Hadoop YARN ResourceManager 未授权访问                               |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Apache Httpd         | CVE-2021-40438     | SSRF         |  -  | Apache HTTP Server 2.4.48 mod_proxy SSRF                             |
| Apache Httpd         | CVE-2021-41773     | FileRead/RCE |  Y  | Apache HTTP Server 2.4.49 路径遍历                                   |
| Apache Httpd         | CVE-2021-42013     | FileRead/RCE |  Y  | Apache HTTP Server 2.4.50 路径遍历                                   |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Apache SkyWalking    | CVE-2020-9483      | SQLinject    |  -  | SkyWalking SQL注入                                                   |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Apache Solr          | CVE-2017-12629     | RCE          |  -  | Solr 远程命令执行                                                    |
| Apache Solr          | CVE-2019-17558     | RCE          |  Y  | Solr Velocity 注入远程命令执行                                       |
| Apache Solr          | CVE-2021-27905     | SSRF/FileRead|  Y  | Solr SSRF/任意文件读取                                               |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Apache Tomcat        | CVE-2017-12615     | FileUpload   |  -  | PUT方法任意文件写入                                                  |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Apache Unomi         | CVE-2020-13942     | RCE          |  Y  | Apache Unomi远程表达式代码执行                                       |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| AppWeb               | CVE-2018-8715      | unAuth       |  -  | AppWeb身份认证绕过                                                   |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Atlassian Confluence | CVE-2015-8399      | FileRead     |  Y  | Confluence任意文件包含                                               |
| Atlassian Confluence | CVE-2019-3396      | FileRead     |  Y  | Confluence路径遍历和命令执行                                         |
| Atlassian Confluence | CVE-2021-26084     | RCE          |  Y  | Confluence Webwork Pre-Auth OGNL表达式命令注入                       |
| Atlassian Confluence | CVE-2022-26134     | RCE          |  Y  | Confluence远程代码执行                                               |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Cisco                | CVE-2020-3580      | XSS          |  -  | 思科ASA/FTD XSS跨站脚本攻击                                          |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Discuz               | wooyun-2010-080723 | RCE          |  Y  | 全局变量防御绕过RCE                                                  |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Django               | CVE-2017-12794     | XSS          |  -  | debug page XSS跨站脚本攻击                                           |
| Django               | CVE-2018-14574     | Redirect     |  -  | CommonMiddleware url重定向                                           |
| Django               | CVE-2019-14234     | SQLinject    |  -  | JSONfield SQL注入                                                    |
| Django               | CVE-2020-9402      | SQLinject    |  -  | GIS SQL注入                                                          |
| Django               | CVE-2021-35042     | SQLinject    |  -  | QuerySet.order_by SQL注入                                            |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Drupal               | CVE-2014-3704      | SQLinject    |  -  | Drupal < 7.32 Drupalgeddon SQL 注入                                  |
| Drupal               | CVE-2017-6920      | RCE          |  -  | Drupal Core 8 PECL YAML 反序列化代码执行                             |
| Drupal               | CVE-2018-7600      | RCE          |  Y  | Drupal Drupalgeddon 2 远程代码执行                                   |
| Drupal               | CVE-2018-7602      | RCE          |  -  | Drupal 远程代码执行                                                  |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| ElasticSearch        | CVE-2014-3120      | RCE          |  Y  | ElasticSearch命令执行                                                |
| ElasticSearch        | CVE-2015-1427      | RCE          |  Y  | ElasticSearch Groovy 沙盒绕过&&代码执行                              |
| ElasticSearch        | CVE-2015-3337      | FileRead     |  Y  | ElasticSearch 目录穿越                                               |
| ElasticSearch        | CVE-2015-5531      | FileRead     |  Y  | ElasticSearch 目录穿越                                               |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| F5 BIG-IP            | CVE-2020-5902      | RCE          |  -  | BIG-IP远程代码执行                                                   |
| F5 BIG-IP            | CVE-2022-1388      | unAuth/RCE   |  Y  | BIG-IP远程代码执行                                                   |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Fastjson             | CNVD-2017-02833    | unSerialize  |  Y  | Fastjson <= 1.2.24 反序列化                                          |
| Fastjson             | CNVD-2019-22238    | unSerialize  |  Y  | Fastjson <= 1.2.47 反序列化                                          |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Gitea                | (None)             | unAuth       |  -  | Gitea 1.4.0 未授权访问                                               |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Gitlab               | CVE-2021-22205     | RCE          |  -  | GitLab Pre-Auth 远程命令执行                                         |
| Gitlab               | CVE-2021-22214     | SSRF         |  Y  | Gitlab CI Lint API未授权 SSRF                                        |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Grafana              | CVE-2021-43798     | FileRead     |  Y  | Grafana 8.x 插件模块路径遍历                                         |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Influxdb             | (None)             | unAuth       |  -  | influxdb 未授权访问                                                  |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Jenkins              | CVE-2018-1000861   | RCE          |  Y  | jenkins 远程命令执行                                                 |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Jetty                | CVE-2021-28164     | DSinfo       |  -  | jetty 模糊路径信息泄露                                               |
| Jetty                | CVE-2021-28169     | DSinfo       |  -  | jetty Utility Servlets ConcatServlet 双重解码信息泄露                |
| Jetty                | CVE-2021-34429     | DSinfo       |  -  | jetty 模糊路径信息泄露                                               |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Jupyter              | (None)             | unAuth       |  -  | Jupyter 未授权访问                                                   |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Keycloak             | CVE-2020-10770     | SSRF         |  -  | 使用request_uri调用未经验证的URL                                     |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Landray              | CNVD-2021-28277    | FileRead/SSRF|  Y  | 蓝凌OA 任意文件读取/SSRF                                             |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Mini Httpd           | CVE-2018-18778     | FileRead     |  -  | mini_httpd 任意文件读取                                              |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| mongo-express        | CVE-2019-10758     | RCE          |  Y  | 未授权远程代码执行                                                   |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Nexus Repository     | CVE-2019-5475      | RCE          |  Y  | 2.x yum插件 远程命令执行                                             |
| Nexus Repository     | CVE-2019-7238      | RCE          |  Y  | 3.x 远程命令执行                                                     |
| Nexus Repository     | CVE-2019-15588     | RCE          |  Y  | 2019-5475的绕过                                                      |
| Nexus Repository     | CVE-2020-10199     | RCE          |  Y  | 3.x 远程命令执行                                                     |
| Nexus Repository     | CVE-2020-10204     | RCE          |  Y  | 3.x 远程命令执行                                                     |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Nodejs               | CVE-2017-14849     | FileRead     |  Y  | Node.js目录穿越                                                      |
| Nodejs               | CVE-2021-21315     | RCE          |  Y  | Node.js命令执行                                                      |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| NodeRED              | CVE-2021-3223      | FileRead     |  Y  | Node-RED 任意文件读取                                                |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| phpMyadmin           | WooYun-2016-199433 | unSerialize  |  -  | phpMyadmin Scripts/setup.php 反序列化                                |
| phpMyadmin           | CVE-2018-12613     | FileInclude  |  Y  | phpMyadmin 4.8.1 远程文件包含                                        |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| PHPUnit              | CVE-2017-9841      | RCE          |  Y  | PHPUnit 远程代码执行                                                 |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Ruby on Rails        | CVE-2018-3760      | FileRead     |  Y  | Ruby on Rails 路径遍历                                               |
| Ruby on Rails        | CVE-2019-5418      | FileRead     |  Y  | Ruby on Rails 任意文件读取                                           |
| Ruby on Rails        | CVE-2020-8163      | RCE          |  -  | Ruby on Rails 命令执行                                               |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| ShowDoc              | CNVD-2020-26585    | FileUpload   |  -  | ShowDoc 任意文件上传                                                 |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Spring               | CVE-2016-4977      | RCE          |  -  | Spring Security OAuth2 远程命令执行                                  |
| Spring               | CVE-2017-8046      | RCE          |  -  | Spring Data Rest 远程命令执行                                        |
| Spring               | CVE-2018-1273      | RCE          |  Y  | Spring Data Commons 远程命令执行                                     |
| Spring               | CVE-2020-5410      | FileRead     |  Y  | Spring Cloud目录遍历                                                 |
| Spring               | CVE-2021-21234     | FileRead     |  Y  | Spring Boot目录遍历                                                  |
| Spring               | CVE-2022-22947     | RCE          |  -  | Spring Cloud Gateway SpEl远程代码执行                                |
| Spring               | CVE-2022-22963     | RCE          |  Y  | Spring Cloud Function SpEL远程代码执行                               |
| Spring               | CVE-2022-22965     | RCE          |  -  | Spring Framework远程代码执行                                         |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Supervisor           | CVE-2017-11610     | RCE          |  -  | Supervisor 远程命令执行                                              |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| ThinkPHP             | CVE-2018-1002015   | RCE          |  Y  | ThinkPHP5.x 远程代码执行                                             |
| ThinkPHP             | CNVD-2018-24942    | RCE          |  Y  | 未开启强制路由导致RCE                                                |
| ThinkPHP             | CNNVD-201901-445   | RCE          |  Y  | 核心类Request远程代码执行                                            |
| ThinkPHP             | CNVD-2022-86535    | RCE          |  -  | ThinkPHP 多语言模块命令执行                                          |
| ThinkPHP             | (None)             | RCE          |  -  | ThinkPHP2.x 远程代码执行                                             |
| ThinkPHP             | (None)             | SQLinject    |  -  | ThinkPHP5 ids参数SQL注入                                             |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Ueditor              | (None)             | SSRF         |  -  | Ueditor编辑器SSRF                                                    |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| uWSGI-PHP            | CVE-2018-7490      | FileRead     |  Y  | uWSGI-PHP目录穿越                                                    |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Oracle Weblogic      | CVE-2014-4210      | SSRF         |  -  | Weblogic 服务端请求伪造                                              |
| Oracle Weblogic      | CVE-2017-10271     | unSerialize  |  -  | Weblogic XMLDecoder反序列化                                          |
| Oracle Weblogic      | CVE-2019-2725      | unSerialize  |  -  | Weblogic wls9_async反序列化                                          |
| Oracle Weblogic      | CVE-2020-14750     | unAuth       |  -  | Weblogic 权限验证绕过                                                |
| Oracle Weblogic      | CVE-2020-14882     | RCE          |  Y  | Weblogic 未授权命令执行                                              |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Webmin               | CVE-2019-15107     | RCE          |  Y  | Webmin Pre-Auth 远程代码执行                                         |
| Webmin               | CVE-2019-15642     | RCE          |  Y  | Webmin 远程代码执行                                                  |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Yonyou               | CNNVD-201610-923   | SQLinject    |  -  | 用友GRP-U8 Proxy SQL注入                                             |
| Yonyou               | CNVD-2021-30167    | RCE          |  Y  | 用友NC BeanShell远程命令执行                                         |
| Yonyou               | (None)             | FileRead     |  -  | 用友ERP-NC NCFindWeb目录遍历                                         |
| Yonyou               | (None)             | DSinfo       |  -  | 用友U8 OA getSessionList.jsp 敏感信息泄漏                            |
| Yonyou               | (None)             | SQLinject    |  -  | 用友U8 OA test.jsp SQL注入                                           |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
| Zabbix               | CVE-2016-10134     | SQLinject    |  -  | latest.php或jsrpc.php存在sql注入                                     |
+----------------------+--------------------+--------------+-----+----------------------------------------------------------------------+
vulcat-1.1.9/2023.02.10
100/Poc
50/Shell
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

## Star History
[![Star History Chart](https://api.star-history.com/svg?repos=CLincat/vulcat&type=Timeline)](https://star-history.com/#Ashutosh00710/github-readme-activity-graph&Timeline)