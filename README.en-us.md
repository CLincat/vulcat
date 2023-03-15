# vulcat

[![python](https://img.shields.io/badge/Python-3-blue?logo=python)](https://shields.io/)
[![version](https://img.shields.io/badge/Version-2.0.0-blue)](https://shields.io/)
[![license](https://img.shields.io/badge/LICENSE-GPL-yellow)](https://shields.io/)
[![stars](https://img.shields.io/github/stars/CLincat/vulcat?color=red)](https://shields.io/)
[![forks](https://img.shields.io/github/forks/CLincat/vulcat?color=red)](https://shields.io/)

**[中文版本(Chinese version)](/README.md)**

* **document：https://clincat.github.io/vulcat-docs/**

(Monthly update)<br>
* Vulcat can be used to scan for vulnerabilities on the Web side. When a vulnerability is discovered, the target URL and Payload are prompted. Users can manually verify the vulnerability according to the prompt<br/>
* Users can also write their own POC and add it to vulcat for scanning, You are also welcome to contribute your POC to the project
* If you have any ideas, suggestions, or bugs, you can issue

## Code of Conduct and Disclaimer
* **Before using this tool, ensure that your actions comply with local laws and regulations and that you have obtained relevant authorization.**

* **This tool is only for enterprises and individuals with legal authorization and is intended to enhance cyberspace security.**

* **If you commit any illegal acts or cause any serious consequences during the use of the tool, you shall bear the corresponding liabilities by yourself, and we will not assume any legal and joint liability.**

## Installation & Usage
The tool is developed based on python3. Python3.8 or later is recommended

* Git: `git clone https://github.com/CLincat/vulcat.git`
* Zip: [click me](https://github.com/CLincat/vulcat/archive/refs/heads/main.zip)

```
git clone https://github.com/CLincat/vulcat.git
cd vulcat
pip3 install -r requirements.txt
python3 vulcat.py -h
```
```
Usage:
By using this tool, you agree to the "Code of Conduct and Disclaimer" in "vulcat/README.md; If you do not agree, do not use this tool."


Usage: python3 vulcat.py <options>
Examples:
python3 vulcat.py -h
python3 vulcat.py --list
python3 vulcat.py -u https://www.example.com/
python3 vulcat.py -f url.txt -o html
python3 vulcat.py -u https://www.example.com/ -v httpd --log 3
python3 vulcat.py -u https://www.example.com/ -v cnvd-2018-24942 --shell
```

## Options
```
Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit

  Target:
    Specify scan target

    -u URL, --url=URL   A url (e.g. -u http://www.example.com/)
    -f FILE, --file=FILE
                        A file containing multiple urls, one URL per line
                        (e.g. -f url.txt)
    -r, --recursive     Recursively scan each directory of the URL

  Optional:
    Optional function options

    -t THREAD, --thread=THREAD
                        The number of threads (default: 2)
    --delay=DELAY       Delay time/s (default: 1)
    --timeout=TIMEOUT   Timeout/s (default: 10)
    --user-agent=UA     Customize the User-Agent
    --cookie=COOKIE     Add a cookie (e.g. --cookie "PHPSESSID=123456789")
    --auth=AUTHORIZATION
                        Add a Authorization (e.g. --auth "Basic
                        YWRtaW46YWRtaW4=")

  Log:
    Debug information

    --log=LOG           The log level, Optional 1-6 (default: 1) [level 2:
                        Framework name + Vulnerability number + status code]
                        [level 3: Level 2 content + request method + request
                        target +POST data] [level 4: Level 2 content + request
                        packet] [Level 5: Level 4 content + response header]
                        [level 6: Level 5 content + response content]

  Proxy:
    Proxy server

    --http-proxy=HTTP_PROXY
                        The HTTP/HTTPS proxy (e.g. --http-proxy
                        127.0.0.1:8080)
    --socks4-proxy=SOCKS4_PROXY
                        The socks4 proxy(e.g. --socks4-proxy 127.0.0.1:8080)
    --socks5-proxy=SOCKS5_PROXY
                        The socks5 proxy(e.g. --socks5-proxy 127.0.0.1:8080 or
                        admin:123456@127.0.0.1:8080)

  Application:
    Specify the target type for the scan

    -v VULN, --vuln=VULN
                        Specify the vulnerability number,With -a/--application
                        to scan a single vulnerability,You can use --list to
                        see the vulnerability number,vulnerabilities that do
                        not have a vulnerability number are not supported.The
                        number does not discriminate between sizes, and the
                        symbol - and _ are acceptable (e.g. -a fastjson -v
                        cnVD-2019-22238 or -a Tomcat -v CVE-2017_12615)
    --shell             Use with the -a and -v parameters, After the Poc scan,
                        if the vulnerability exists, enter the Shell
                        interaction mode of the vulnerability; You can use
                        --list to see Shell support vulnerabilities. (e.g. -a
                        httpd -v CVE-2021-42013 -x)
    --type=VULNTYPE     Use with --shell parameter to specify the type of
                        vulnerability and carry out corresponding Shell
                        operations (e.g. --shell --type RCE)

  Api:
    The third party Api

    --dns=DNS           DNS platform, auxiliary verification without echo
                        vulnerability. ceye/dnslog-pw/dnslog-cn (e.g. --dns
                        ceye) (Default: auto)

  Save:
    Save scan results

    -o OUTPUT, --output=OUTPUT
                        Save the scan results in txt/json/html format, no
                        vulnerability will not generate files (e.g. -o html)

  General:
    General operating parameter

    --no-waf            Disable WAF detection
    --no-poc            Disable scanning for security vulnerabilities
    --batch             The yes/no option does not require user input. The
                        default option is used

  Lists:
    Vulnerability list

    --list              View all payload
```

## language
You can change the language of vulcat, currently only Chinese and English

* Open the vulcat/config.yaml
* Modify the value of "language" and save the file to switch the Vulcat language

```
# Language, default is English en-us, Chinese is zh-cn
language: en-us
```

## Dnslog
You can customize http://ceye.io

* Open the vulcat/config.yaml
* Find the following code, replace Null with your own domain name and token, and save the file
```
ceye-domain: Null
ceye-token: Null
```

## Custom POC
* How do I write my own vulnerability POC and add it to vulcat
* Find vulcat/payloads/demo.py, which is a POC template in Vulcat (semi-finished) and requires the user to fill in the rest of the code

* **Modify the steps:**
1. Make a copy of demo.py and save it to prevent template loss. Then change the name of the POC (such as test.py)

2. Then follow the tips in demo.py to fill in your own code and introduce POC into vulcat

## Payloads List
<details>
<summary><strong>vulcat Payloads List: [Click on]</strong></summary>

```
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| Payloads                                                 | Sh  | Description                                                  |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| 74cms-v5.0.1-sqlinject                                   |  -  | v5.0.1 AjaxPersonalController.class.php SQLinject            |
| 74cms-v6.0.4-xss                                         |  -  | v6.0.4 help center search box-XSS                            |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| alibaba-druid-unauth                                     |  -  | Alibaba Druid unAuthorized                                   |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| alibaba-nacos-cve-2021-29441-unauth                      |  -  | Alibaba Nacos unAuthorized                                   |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| apache-airflow-cve-2020-17526-unauth                     |  -  | Apache Airflow Authentication bypass                         |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| apache-apisix-cve-2020-13945-unauth                      |  -  | Apache APISIX default access token                           |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| apache-druid-cve-2021-25646-rce                          |  Y  | Apache Druid Remote Code Execution                           |
| apache-druid-cve-2021-36749-fileread                     |  Y  | Apache Druid arbitrary file reading                          |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| apache-flink-cve-2020-17519-fileread                     |  Y  | Apache Flink Directory traversal                             |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| apache-hadoop-unauth                                     |  -  | Apache Hadoop YARN ResourceManager unAuthorized              |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| apache-httpd-cve-2021-40438-ssrf                         |  -  | Apache HTTP Server 2.4.48 mod_proxy SSRF                     |
| apache-httpd-cve-2021-41773-rce-fileread                 |  Y  | Apache HTTP Server 2.4.49 Directory traversal                |
| apache-httpd-cve-2021-42013-rce-fileread                 |  Y  | Apache HTTP Server 2.4.50 Directory traversal                |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| apache-skywalking-cve-2020-9483-sqlinject                |  -  | SkyWalking SQLinject                                         |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| apache-solr-cve-2017-12629-rce                           |  -  | Solr Remote code execution                                   |
| apache-solr-cve-2019-17558-rce                           |  Y  | Solr RCE Via Velocity Custom Template                        |
| apache-solr-cve-2021-27905-ssrf-fileread                 |  Y  | Solr SSRF/FileRead                                           |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| apache-tomcat-cve-2017-12615-fileupload                  |  -  | Put method writes to any file                                |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| apache-unomi-cve-2020-13942-rce                          |  Y  | Apache Unomi Remote Express Language Code Execution          |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| appweb-cve-2018-8715-unauth                              |  -  | AppWeb Authentication bypass                                 |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| atlassian-confluence-cve-2015-8399-fileread-fileinclude  |  Y  | Confluence any file include                                  |
| atlassian-confluence-cve-2019-3396-fileread              |  Y  | Confluence Directory traversal && RCE                        |
| atlassian-confluence-cve-2021-26084-rce                  |  Y  | Confluence OGNL expression command injection                 |
| atlassian-confluence-cve-2022-26134-rce                  |  Y  | Confluence Remote code execution                             |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| cisco-cve-2020-3580-xss                                  |  -  | Cisco ASA/FTD XSS                                            |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| discuz-wooyun-2010-080723-rce                            |  Y  | Remote code execution                                        |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| django-cve-2017-12794-xss                                |  -  | Django debug page XSS                                        |
| django-cve-2018-14574-redirect                           |  -  | Django CommonMiddleware URL Redirect                         |
| django-cve-2019-14234-sqlinject                          |  -  | Django JSONfield SQLinject                                   |
| django-cve-2020-9402-sqlinject                           |  -  | Django GIS SQLinject                                         |
| django-cve-2021-35042-sqlinject                          |  -  | Django QuerySet.order_by SQLinject                           |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| drupal-cve-2014-3704-sqlinject                           |  -  | Drupal < 7.32 Drupalgeddon SQLinject                         |
| drupal-cve-2017-6920-rce                                 |  -  | Drupal Core 8 PECL YAML Remote code execution                |
| drupal-cve-2018-7600-rce                                 |  Y  | Drupal Drupalgeddon 2 Remote code execution                  |
| drupal-cve-2018-7602-rce                                 |  -  | Drupal Remote code execution                                 |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| elasticsearch-cve-2014-3120-rce                          |  Y  | ElasticSearch Remote code execution                          |
| elasticsearch-cve-2015-1427-rce                          |  Y  | ElasticSearch Groovy Sandbox to bypass && RCE                |
| elasticsearch-cve-2015-3337-fileread                     |  Y  | ElasticSearch Directory traversal                            |
| elasticsearch-cve-2015-5531-fileread                     |  Y  | ElasticSearch Directory traversal                            |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| f5bigip-cve-2020-5902-rce-fileread                       |  -  | BIG-IP Remote code execution                                 |
| f5bigip-cve-2022-1388-unauth-rce                         |  Y  | BIG-IP Authentication bypass RCE                             |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| fastjson-cnvd-2017-02833-rce                             |  Y  | Fastjson <= 1.2.24 deSerialization                           |
| fastjson-cnvd-2019-22238-rce                             |  Y  | Fastjson <= 1.2.47 deSerialization                           |
| fastjson-v1.2.62-rce                                     |  Y  | Fastjson <= 1.2.62 deSerialization                           |
| fastjson-v1.2.66-rce                                     |  Y  | Fastjson <= 1.2.66 deSerialization                           |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| gitea-unauth-fileread-rce                                |  -  | Gitea 1.4.0 unAuthorized                                     |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| gitlab-cve-2021-22205-rce.py                             |  -  | GitLab Pre-Auth Remote code execution                        |
| gitlab-cve-2021-22214-ssrf                               |  Y  | Gitlab CI Lint API SSRF                                      |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| gocd-cve-2021-43287-fileread                             |  Y  | GoCD Business Continuity FileRead                            |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| grafana-cve-2021-43798-fileread                          |  Y  | Grafana 8.x Directory traversal                              |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| influxdb-unauth                                          |  -  | influxdb unAuthorized                                        |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| jboss-unauth                                             |  -  | JBoss unAuthorized                                           |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| jenkins-cve-2018-1000861-rce                             |  Y  | jenkins Remote code execution                                |
| jenkins-unauth                                           |  Y  | Jenkins unAuthorized                                         |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| jetty-cve-2021-28164-dsinfo                              |  -  | jetty Disclosure information                                 |
| jetty-cve-2021-28169-dsinfo                              |  -  | jetty Servlets ConcatServlet Disclosure information          |
| jetty-cve-2021-34429-dsinfo                              |  -  | jetty Disclosure information                                 |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| joomla-cve-2017-8917-sqlinject                           |  -  | Joomla3.7 Core com_fields SQLinject                          |
| joomla-cve-2023-23752-unauth                             |  -  | Joomla unAuthorized                                          |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| jupyter-unauth                                           |  -  | Jupyter unAuthorized                                         |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| keycloak-cve-2020-10770-ssrf                             |  -  | request_uri SSRF                                             |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| landray-oa-cnvd-2021-28277-ssrf-fileread                 |  Y  | Landray-OA FileRead/SSRF                                     |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| minihttpd-cve-2018-18778-fileread                        |  -  | mini_httpd FileRead                                          |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| mongoexpress-cve-2019-10758-rce                          |  Y  | Remote code execution                                        |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| nexus-cve-2019-5475-rce                                  |  Y  | 2.x yum Remote code execution                                |
| nexus-cve-2019-7238-rce                                  |  Y  | 3.x Remote code execution                                    |
| nexus-cve-2019-15588-rce                                 |  Y  | 2019-5475 Bypass                                             |
| nexus-cve-2020-10199-rce                                 |  Y  | 3.x Remote code execution                                    |
| nexus-cve-2020-10204-rce                                 |  Y  | 3.x Remote code execution                                    |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| nodejs-cve-2017-14849-fileread                           |  Y  | Node.js Directory traversal                                  |
| nodejs-cve-2021-21315-rce                                |  Y  | Node.js Remote code execution                                |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| nodered-cve-2021-3223-fileread                           |  Y  | Node-RED Directory traversal                                 |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| phpmyadmin-cve-2018-12613-fileinclude-fileread           |  -  | phpMyadmin Scripts/setup.php Deserialization                 |
| phpmyadmin-wooyun-2016-199433-unserialize                |  Y  | phpMyadmin 4.8.1 Remote File Inclusion                       |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| phpunit-cve-2017-9841-rce                                |  Y  | PHPUnit Remote code execution                                |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| ruby-on-rails-cve-2018-3760-fileread                     |  Y  | Ruby on Rails Directory traversal                            |
| ruby-on-rails-cve-2019-5418-fileread                     |  Y  | Ruby on Rails FileRead                                       |
| ruby-on-rails-cve-2020-8163-rce                          |  -  | Ruby on Rails Remote code execution                          |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| showdoc-cnvd-2020-26585-fileupload                       |  -  | ShowDoc writes to any file                                   |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| spring-security-oauth-cve-2016-4977-rce                  |  -  | Spring Security OAuth2 Remote Command Execution              |
| spring-data-rest-cve-2017-8046-rce                       |  -  | Spring Data Rest Remote Command Execution                    |
| spring-data-commons-cve-2018-1273-rce                    |  Y  | Spring Data Commons Remote Command Execution                 |
| spring-cloud-config-cve-2020-5410-fileread               |  Y  | Spring Cloud Directory traversal                             |
| spring-boot-cve-2021-21234-fileread                      |  Y  | Spring Boot Directory traversal                              |
| spring-cloud-gateway-cve-2022-22947-rce                  |  -  | Spring Cloud Gateway SpEl Remote code execution              |
| spring-cloud-function-cve-2022-22963-rce                 |  Y  | Spring Cloud Function SpEL Remote code execution             |
| spring-cve-2022-22965-rce                                |  -  | Spring Framework Remote code execution                       |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| supervisor-cve-2017-11610-rce                            |  -  | Supervisor Remote Command Execution                          |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| thinkphp-cve-2018-1002015-rce                            |  Y  | ThinkPHP5.x Remote code execution                            |
| thinkphp-cnvd-2018-24942-rce                             |  Y  | The forced route is not enabled RCE                          |
| thinkphp-cnnvd-201901-445-rce                            |  Y  | Core class Request Remote code execution                     |
| thinkphp-cnvd-2022-86535-rce                             |  -  | ThinkPHP "think-lang" Remote code execution                  |
| thinkphp-2.x-rce                                         |  -  | ThinkPHP2.x Remote code execution                            |
| thinkphp-5-ids-sqlinject                                 |  -  | ThinkPHP5 ids SQLinject                                      |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| ueditor-ssrf                                             |  -  | Ueditor SSRF                                                 |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| uwsgiphp-cve-2018-7490-fileread                          |  Y  | uWSGI-PHP Directory traversal                                |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| vmware-vcenter-2020-10-fileread                          |  Y  | In 2020 VMware vCenter 6.5 Any file read                     |
| vmware-vcenter-cve-2021-21972-fileupload-rce             |  -  | VMware vSphere Client RCE                                    |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| oracle-weblogic-cve-2014-4210-ssrf                       |  -  | Weblogic SSRF                                                |
| oracle-weblogic-cve-2017-10271-unserialize               |  -  | Weblogic XMLDecoder deSerialization                          |
| oracle-weblogic-cve-2019-2725-unserialize                |  -  | Weblogic wls9_async deSerialization                          |
| oracle-weblogic-cve-2020-14750-bypass                    |  -  | Weblogic Authentication bypass                               |
| oracle-weblogic-cve-2020-14882-rce-unauth                |  Y  | Weblogic Unauthorized command execution                      |
| oracle-weblogic-cve-2021-2109-rce                        |  -  | Weblogic LDAP Remote code execution                          |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| webmin-cve-2019-15107-rce                                |  Y  | Webmin Pre-Auth Remote code execution                        |
| webmin-cve-2019-15642-rce                                |  Y  | Webmin Remote code execution                                 |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| yonyou-grp-u8-cnnvd-201610-923-sqlinject                 |  -  | Yonyou-GRP-U8 Proxy SQLinject                                |
| yonyou-nc-cnvd-2021-30167-rce                            |  Y  | Yonyou-NC BeanShell Remote code execution                    |
| yonyou-erp-nc-ncfindweb-fileread                         |  -  | Yonyou-ERP-NC NCFindWeb Directory traversal                  |
| yonyou-u8-oa-getsession-dsinfo                           |  -  | Yonyou-U8-OA getSessionList.jsp Disclosure info              |
| yonyou-u8-oa-test.jsp-sqlinject                          |  -  | Yonyou-U8-OA test.jsp SQLinject                              |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
| zabbix-cve-2016-10134-sqlinject                          |  -  | latest.php or jsrpc.php SQLinject                            |
+----------------------------------------------------------+-----+--------------------------------------------------------------+
vulcat-2.0.0/2023.03.15
112/Poc
55/Shell
```
</details>

## Thanks
* [vulmap](https://github.com/zhzyker/vulmap)
* [sqlmap](https://github.com/sqlmapproject/sqlmap)
* [dirsearch](https://github.com/maurosoria/dirsearch)
* [HackRequests](https://github.com/boy-hack/hack-requests)
* [vulhub](https://github.com/vulhub/vulhub)
* [vulfocus](https://github.com/fofapro/vulfocus)
* [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap/)
* [Xray](github.com/chaitin/xray)

## Document

[document](https://clincat.github.io/vulcat-docs/)

## Star History
[![Star History Chart](https://api.star-history.com/svg?repos=CLincat/vulcat&type=Timeline)](https://star-history.com/#Ashutosh00710/github-readme-activity-graph&Timeline)