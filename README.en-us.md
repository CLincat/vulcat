# vulcat

[![python](https://img.shields.io/badge/Python-3-blue?logo=python)](https://shields.io/)
[![version](https://img.shields.io/badge/Version-1.1.8-blue)](https://shields.io/)
[![license](https://img.shields.io/badge/LICENSE-GPL-yellow)](https://shields.io/)
[![stars](https://img.shields.io/github/stars/CLincat/vulcat?color=red)](https://shields.io/)
[![forks](https://img.shields.io/github/forks/CLincat/vulcat?color=red)](https://shields.io/)

**[中文版本(Chinese version)](/README.md)**

(Monthly update)<br>
* Vulcat can be used to scan for vulnerabilities on the Web side. When a vulnerability is discovered, the target URL and Payload are prompted. Users can manually verify the vulnerability according to the prompt<br/>
* Users can also write their own POC and add it to vulcat for scanning, You are also welcome to contribute your POC to the project
* If you have any ideas, suggestions, or bugs, you can issue

**Web applications that currently support scanning:**
> AlibabaDruid, AlibabaNacos, ApacheAirflow, ApacheAPISIX, ApacheDruid, ApacheFlink, ApacheHadoop, ApacheHttpd, ApacheSkywalking, ApacheSolr, ApacheTomcat, AppWeb, AtlassianConfluence, Cicso, Discuz, Django, Drupal, ElasticSearch, F5-BIG-IP, Fastjson, Gitea, Gitlab, Grafana, Influxdb, RubyOnRails, Jenkins, Jetty, Jupyter, Keycloak, Landray-OA, MiniHttpd, mongo-express, Nexus, Node.js, NodeRED, phpMyAdmin, phpUnit, ShowDoc, Spring, Supervisor, ThinkPHP, Ueditor, Weblogic, Webmin, Yonyou, Zabbix

**You can also check out the "Vulnerabilitys List" below to see which vulnerabilities vulcat supports scanning**

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
python3 vulcat.py -u https://www.example.com/
python3 vulcat.py -u https://www.example.com/ -a thinkphp --log 3
python3 vulcat.py -u https://www.example.com/ -a tomcat -v CVE-2017-12615
python3 vulcat.py -f url.txt -t 10 -o html
python3 vulcat.py --list
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

    -a APPLICATION, --application=APPLICATION
                        Specifies the target type, for supported frameworks,
                        see the tips at the bottom, separated by commas (e.g.
                        thinkphp / thinkphp,weblogic) (default: auto)
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

  Api:
    The third party Api

    --dns=DNS           DNS platform, auxiliary verification without echo
                        vulnerability. dnslog.cn/ceye.io (optional parameter:
                        dnslog/ceye e.g. --dns ceye) (automatically selected
                        by default, ceye is preferred, and dnglog is
                        automatically changed when ceye is unavailable)

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

  Supported target types(Case insensitive):
    AliDruid, airflow, apisix, apachedruid, appweb, cisco, confluence,
    discuz, django, drupal, elasticsearch, f5bigip, fastjson, flink,
    gitea, gitlab, grafana, influxdb, hadoop, httpd, jenkins, jetty,
    jupyter, keycloak, landray, minihttpd, mongoexpress, nexus, nacos,
    nodejs, nodered, phpmyadmin, phpunit, rails, showdoc, solr, spring,
    supervisor, skywalking, thinkphp, tomcat, ueditor, weblogic, webmin,
    yonyou, zabbix
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

## Vulnerabilitys List
<details>
<summary><strong>The current web vulnerabilities that support scanning: [Click on]</strong></summary>

```
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Target               | Vuln id            | Vuln Type    | Sh  | Description                                                  |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Alibaba Druid        | (None)             | unAuth       |  -  | Alibaba Druid unAuthorized                                   |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Alibaba Nacos        | CVE-2021-29441     | unAuth       |  -  | Alibaba Nacos unAuthorized                                   |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Apache Airflow       | CVE-2020-17526     | unAuth       |  -  | Apache Airflow Authentication bypass                         |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Apache APISIX        | CVE-2020-13945     | unAuth       |  -  | Apache APISIX default access token                           |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Apache Druid         | CVE-2021-25646     | RCE          |  Y  | Apache Druid Remote Code Execution                           |
| Apache Druid         | CVE-2021-36749     | FileRead     |  Y  | Apache Druid arbitrary file reading                          |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Apache Flink         | CVE-2020-17519     | FileRead     |  Y  | Apache Flink Directory traversal                             |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Apache Hadoop        | (None)             | unAuth       |  -  | Apache Hadoop YARN ResourceManager unAuthorized              |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Apache Httpd         | CVE-2021-40438     | SSRF         |  -  | Apache HTTP Server 2.4.48 mod_proxy SSRF                     |
| Apache Httpd         | CVE-2021-41773     | FileRead/RCE |  Y  | Apache HTTP Server 2.4.49 Directory traversal                |
| Apache Httpd         | CVE-2021-42013     | FileRead/RCE |  Y  | Apache HTTP Server 2.4.50 Directory traversal                |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Apache SkyWalking    | CVE-2020-9483      | SQLinject    |  -  | SkyWalking SQLinject                                         |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Apache Solr          | CVE-2017-12629     | RCE          |  -  | Solr Remote code execution                                   |
| Apache Solr          | CVE-2019-17558     | RCE          |  Y  | Solr RCE Via Velocity Custom Template                        |
| Apache Solr          | CVE-2021-27905     | SSRF/FileRead|  Y  | Solr SSRF/FileRead                                           |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Apache Tomcat        | CVE-2017-12615     | FileUpload   |  -  | Put method writes to any file                                |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Apache Unomi         | CVE-2020-13942     | RCE          |  Y  | Apache Unomi Remote Express Language Code Execution          |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| AppWeb               | CVE-2018-8715      | unAuth       |  -  | AppWeb Authentication bypass                                 |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Atlassian Confluence | CVE-2015-8399      | FileRead     |  Y  | Confluence any file include                                  |
| Atlassian Confluence | CVE-2019-3396      | FileRead     |  Y  | Confluence Directory traversal && RCE                        |
| Atlassian Confluence | CVE-2021-26084     | RCE          |  Y  | Confluence OGNL expression command injection                 |
| Atlassian Confluence | CVE-2022-26134     | RCE          |  Y  | Confluence Remote code execution                             |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Cisco                | CVE-2020-3580      | XSS          |  -  | Cisco ASA/FTD XSS                                            |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Discuz               | wooyun-2010-080723 | RCE          |  Y  | Remote code execution                                        |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Django               | CVE-2017-12794     | XSS          |  -  | Django debug page XSS                                        |
| Django               | CVE-2018-14574     | Redirect     |  -  | Django CommonMiddleware URL Redirect                         |
| Django               | CVE-2019-14234     | SQLinject    |  -  | Django JSONfield SQLinject                                   |
| Django               | CVE-2020-9402      | SQLinject    |  -  | Django GIS SQLinject                                         |
| Django               | CVE-2021-35042     | SQLinject    |  -  | Django QuerySet.order_by SQLinject                           |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Drupal               | CVE-2014-3704      | SQLinject    |  -  | Drupal < 7.32 Drupalgeddon SQLinject                         |
| Drupal               | CVE-2017-6920      | RCE          |  -  | Drupal Core 8 PECL YAML Remote code execution                |
| Drupal               | CVE-2018-7600      | RCE          |  Y  | Drupal Drupalgeddon 2 Remote code execution                  |
| Drupal               | CVE-2018-7602      | RCE          |  -  | Drupal Remote code execution                                 |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| ElasticSearch        | CVE-2014-3120      | RCE          |  Y  | ElasticSearch Remote code execution                          |
| ElasticSearch        | CVE-2015-1427      | RCE          |  Y  | ElasticSearch Groovy Sandbox to bypass && RCE                |
| ElasticSearch        | CVE-2015-3337      | FileRead     |  Y  | ElasticSearch Directory traversal                            |
| ElasticSearch        | CVE-2015-5531      | FileRead     |  Y  | ElasticSearch Directory traversal                            |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| F5 BIG-IP            | CVE-2020-5902      | RCE          |  -  | BIG-IP Remote code execution                                 |
| F5 BIG-IP            | CVE-2022-1388      | unAuth/RCE   |  Y  | BIG-IP Remote code execution                                 |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Fastjson             | CNVD-2017-02833    | unSerialize  |  -  | Fastjson <= 1.2.24 deSerialization                           |
| Fastjson             | CNVD-2019-22238    | unSerialize  |  -  | Fastjson <= 1.2.47 deSerialization                           |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Gitea                | (None)             | unAuth       |  -  | Gitea 1.4.0 unAuthorized                                     |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Gitlab               | CVE-2021-22205     | RCE          |  -  | GitLab Pre-Auth Remote code execution                        |
| Gitlab               | CVE-2021-22214     | SSRF         |  -  | Gitlab CI Lint API SSRF                                      |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Grafana              | CVE-2021-43798     | FileRead     |  Y  | Grafana 8.x Directory traversal                              |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Influxdb             | (None)             | unAuth       |  -  | influxdb unAuthorized                                        |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Jenkins              | CVE-2018-1000861   | RCE          |  -  | jenkins Remote code execution                                |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Jetty                | CVE-2021-28164     | DSinfo       |  -  | jetty Disclosure information                                 |
| Jetty                | CVE-2021-28169     | DSinfo       |  -  | jetty Servlets ConcatServlet Disclosure information          |
| Jetty                | CVE-2021-34429     | DSinfo       |  -  | jetty Disclosure information                                 |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Jupyter              | (None)             | unAuth       |  -  | Jupyter unAuthorized                                         |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Keycloak             | CVE-2020-10770     | SSRF         |  -  | request_uri SSRF                                             |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Landray              | CNVD-2021-28277    | FileRead/SSRF|  Y  | Landray-OA FileRead/SSRF                                     |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Mini Httpd           | CVE-2018-18778     | FileRead     |  -  | mini_httpd FileRead                                          |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| mongo-express        | CVE-2019-10758     | RCE          |  -  | Remote code execution                                        |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Nexus Repository     | CVE-2019-5475      | RCE          |  Y  | 2.x yum Remote code execution                                |
| Nexus Repository     | CVE-2019-7238      | RCE          |  -  | 3.x Remote code execution                                    |
| Nexus Repository     | CVE-2019-15588     | RCE          |  Y  | 2019-5475 Bypass                                             |
| Nexus Repository     | CVE-2020-10199     | RCE          |  -  | 3.x Remote code execution                                    |
| Nexus Repository     | CVE-2020-10204     | RCE          |  -  | 3.x Remote code execution                                    |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Nodejs               | CVE-2017-14849     | FileRead     |  Y  | Node.js Directory traversal                                  |
| Nodejs               | CVE-2021-21315     | RCE          |  -  | Node.js Remote code execution                                |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| NodeRED              | CVE-2021-3223      | FileRead     |  Y  | Node-RED Directory traversal                                 |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| phpMyadmin           | WooYun-2016-199433 | unSerialize  |  -  | phpMyadmin Scripts/setup.php Deserialization                 |
| phpMyadmin           | CVE-2018-12613     | FileInclude  |  Y  | phpMyadmin 4.8.1 Remote File Inclusion                       |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| PHPUnit              | CVE-2017-9841      | RCE          |  Y  | PHPUnit Remote code execution                                |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Ruby on Rails        | CVE-2018-3760      | FileRead     |  Y  | Ruby on Rails Directory traversal                            |
| Ruby on Rails        | CVE-2019-5418      | FileRead     |  Y  | Ruby on Rails FileRead                                       |
| Ruby on Rails        | CVE-2020-8163      | RCE          |  -  | Ruby on Rails Remote code execution                          |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| ShowDoc              | CNVD-2020-26585    | FileUpload   |  -  | ShowDoc writes to any file                                   |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Spring               | CVE-2016-4977      | RCE          |  -  | Spring Security OAuth2 Remote Command Execution              |
| Spring               | CVE-2017-8046      | RCE          |  -  | Spring Data Rest Remote Command Execution                    |
| Spring               | CVE-2018-1273      | RCE          |  -  | Spring Data Commons Remote Command Execution                 |
| Spring               | CVE-2020-5410      | FileRead     |  Y  | Spring Cloud Directory traversal                             |
| Spring               | CVE-2021-21234     | FileRead     |  Y  | Spring Boot Directory traversal                              |
| Spring               | CVE-2022-22947     | RCE          |  -  | Spring Cloud Gateway SpEl Remote code execution              |
| Spring               | CVE-2022-22963     | RCE          |  -  | Spring Cloud Function SpEL Remote code execution             |
| Spring               | CVE-2022-22965     | RCE          |  -  | Spring Framework Remote code execution                       |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Supervisor           | CVE-2017-11610     | RCE          |  -  | Supervisor Remote Command Execution                          |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| ThinkPHP             | CVE-2018-1002015   | RCE          |  Y  | ThinkPHP5.x Remote code execution                            |
| ThinkPHP             | CNVD-2018-24942    | RCE          |  Y  | The forced route is not enabled RCE                          |
| ThinkPHP             | CNNVD-201901-445   | RCE          |  Y  | Core class Request Remote code execution                     |
| ThinkPHP             | CNVD-2022-86535    | RCE          |  -  | ThinkPHP "think-lang" Remote code execution                  |
| ThinkPHP             | (None)             | RCE          |  -  | ThinkPHP2.x Remote code execution                            |
| ThinkPHP             | (None)             | SQLinject    |  -  | ThinkPHP5 ids SQLinject                                      |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Ueditor              | (None)             | SSRF         |  -  | Ueditor SSRF                                                 |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Oracle Weblogic      | CVE-2014-4210      | SSRF         |  -  | Weblogic SSRF                                                |
| Oracle Weblogic      | CVE-2017-10271     | unSerialize  |  -  | Weblogic XMLDecoder deSerialization                          |
| Oracle Weblogic      | CVE-2019-2725      | unSerialize  |  -  | Weblogic wls9_async deSerialization                          |
| Oracle Weblogic      | CVE-2020-14750     | unAuth       |  -  | Weblogic Authentication bypass                               |
| Oracle Weblogic      | CVE-2020-14882     | RCE          |  -  | Weblogic Unauthorized command execution                      |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Webmin               | CVE-2019-15107     | RCE          |  Y  | Webmin Pre-Auth Remote code execution                        |
| Webmin               | CVE-2019-15642     | RCE          |  Y  | Webmin Remote code execution                                 |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Yonyou               | CNNVD-201610-923   | SQLinject    |  -  | Yonyou-GRP-U8 Proxy SQLinject                                |
| Yonyou               | CNVD-2021-30167    | RCE          |  Y  | Yonyou-NC BeanShell Remote code execution                    |
| Yonyou               | (None)             | FileRead     |  -  | Yonyou-ERP-NC NCFindWeb Directory traversal                  |
| Yonyou               | (None)             | DSinfo       |  -  | Yonyou-U8-OA getSessionList.jsp Disclosure info              |
| Yonyou               | (None)             | SQLinject    |  -  | Yonyou-U8-OA test.jsp SQLinject                              |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
| Zabbix               | CVE-2016-10134     | SQLinject    |  -  | latest.php or jsrpc.php SQLinject                            |
+----------------------+--------------------+--------------+-----+--------------------------------------------------------------+
vulcat-1.1.8/2023.01.20
99/Poc
37/Shell
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

## Star History
[![Star History Chart](https://api.star-history.com/svg?repos=CLincat/vulcat&type=Timeline)](https://star-history.com/#Ashutosh00710/github-readme-activity-graph&Timeline)