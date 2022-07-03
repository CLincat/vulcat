# vulcat

* Vulcat can be used to scan for vulnerabilities on the Web side. When a vulnerability is discovered, the target URL and Payload are prompted. Users can manually verify the vulnerability according to the prompt<br/>
* Users can also write their own POC and add it to vulcat for scanning, You are also welcome to contribute your POC to the project
* If you have any ideas, suggestions, or bugs, you can issue

**Web applications that currently support scanning:**
> AlibabaDruid, AlibabaNacos, ApacheAirflow, ApacheAPISIX, ApacheFlink, ApacheSolr, ApacheStruts2, ApacheTomcat, AppWeb, AtlassianConfluence, Cicso, Django, Drupal, ElasticSearch, F5-BIG-IP, Fastjson, Jenkins, Keycloak, NodeRED, ShowDoc, Spring, ThinkPHP, Ueditor, Weblogic, Webmin, Yonyou

<details>
<summary><strong>The current web vulnerabilities that support scanning: [Click on]</strong></summary>

```
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Target               | Vul_id           | Type         | Method   | Description                                                |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Alibaba Druid        | None             | unAuth       | GET      | Alibaba Druid unAuthorized                                 |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Alibaba Nacos        | CVE-2021-29441   | unAuth       | GET/POST | Alibaba Nacos unAuthorized                                 |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Apache Airflow       | CVE-2020-17526   | unAuth       | GET      | Airflow Authentication bypass                              |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Apache APISIX        | CVE-2020-13945   | unAuth       | GET      | Apache APISIX default access token                         |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Apache Flink         | CVE-2020-17519   | FileRead     | GET      | Flink Directory traversal                                  |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Apache Solr          | CVE-2021-27905   | SSRF         | GET/POST | Solr SSRF/FileRead                                         |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Apache Struts2       | S2-001           | RCE          | POST     | Struts2 Remote code execution                              |
| Apache Struts2       | S2-005           | RCE          | GET      | Struts2 Remote code execution                              |
| Apache Struts2       | S2-007           | RCE          | GET      | Struts2 Remote code execution                              |
| Apache Struts2       | S2-008           | RCE          | GET      | Struts2 Remote code execution                              |
| Apache Struts2       | S2-009           | RCE          | GET      | Struts2 Remote code execution                              |
| Apache Struts2       | S2-012           | RCE          | GET      | Struts2 Remote code execution                              |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Apache Tomcat        | CVE-2017-12615   | FileUpload   | PUT      | Put method writes to any file                              |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| AppWeb               | CVE-2018-8715    | unAuth       | GET      | AppWeb Authentication bypass                               |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Atlassian Confluence | CVE-2015-8399    | FileRead     | GET      | Confluence any file include                                |
| Atlassian Confluence | CVE-2019-3396    | RCE/FileRead | POST     | Confluence Directory traversal && RCE                      |
| Atlassian Confluence | CVE-2021-26084   | RCE          | POST     | Confluence OGNL expression command injection               |
| Atlassian Confluence | CVE-2022-26134   | RCE          | GET      | Confluence Remote code execution                           |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Cisco                | CVE-2020-3580    | XSS          | POST     | Cisco ASA/FTD XSS                                          |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Django               | CVE-2017-12794   | XSS          | GET      | Django debug page XSS                                      |
| Django               | CVE-2018-14574   | Redirect     | GET      | Django CommonMiddleware URL Redirect                       |
| Django               | CVE-2019-14234   | SQLinject    | GET      | Django JSONfield SQLinject                                 |
| Django               | CVE-2020-9402    | SQLinject    | GET      | Django GIS SQLinject                                       |
| Django               | CVE-2021-35042   | SQLinject    | GET      | Django QuerySet.order_by SQLinject                         |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Drupal               | CVE-2018-7600    | RCE          | POST     | Drupal Drupalgeddon 2 Remote code execution                |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| ElasticSearch        | CVE-2014-3120    | RCE          | POST     | ElasticSearch Remote code execution                        |
| ElasticSearch        | CVE-2015-1427    | RCE          | POST     | ElasticSearch Groovy Sandbox to bypass && RCE              |
| ElasticSearch        | CVE-2015-3337    | FileRead     | GET      | ElasticSearch Directory traversal                          |
| ElasticSearch        | CVE-2015-5531    | FileRead     | PUT/GET  | ElasticSearch Directory traversal                          |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| F5 BIG-IP            | CVE-2020-5902    | RCE          | GET      | BIG-IP Remote code execution                               |
| F5 BIG-IP            | CVE-2022-1388    | unAuth       | POST     | BIG-IP Authentication bypass                               |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Fastjson             | CNVD-2017-02833  | unSerialize  | POST     | Fastjson <= 1.2.24 deSerialization                         |
| Fastjson             | CNVD-2019-22238  | unSerialize  | POST     | Fastjson <=1.2.47 deSerialization                          |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Jenkins              | CVE-2018-1000861 | RCE          | POST     | jenkins Remote code execution                              |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Keycloak             | CVE-2020-10770   | SSRF         | GET      | request_uri SSRF                                           |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| NodeRED              | CVE-2021-3223    | FileRead     | GET      | Node-RED Directory traversal                               |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| ShowDoc              | CNVD-2020-26585  | FileUpload   | POST     | ShowDoc writes to any file                                 |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Spring               | CVE-2020-5410    | FileRead     | GET      | Spring Cloud Directory traversal                           |
| Spring               | CVE-2021-21234   | FileRead     | GET      | Spring Boot Directory traversal                            |
| Spring               | CVE-2022-22947   | RCE          | POST     | Spring Cloud Gateway SpEl Remote code execution            |
| Spring               | CVE-2022-22963   | RCE          | POST     | Spring Cloud Function SpEL Remote code execution           |
| Spring               | CVE-2022-22965   | RCE          | GET/POST | Spring Framework Remote code execution                     |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| ThinkPHP             | CVE-2018-1002015 | RCE          | GET      | ThinkPHP5.x Remote code execution                          |
| ThinkPHP             | CNVD-2018-24942  | RCE          | GET      | The forced route is not enabled Remote code execution      |
| ThinkPHP             | CNNVD-201901-445 | RCE          | POST     | Core class Request Remote code execution                   |
| ThinkPHP             | None             | RCE          | GET      | ThinkPHP2.x Remote code execution                          |
| ThinkPHP             | None             | SQLinject    | GET      | ThinkPHP5 ids SQLinject                                    |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Ueditor              | None             | SSRF         | GET      | Ueditor SSRF                                               |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Oracle Weblogic      | CVE-2014-4210    | SSRF         | GET      | Weblogic SSRF                                              |
| Oracle Weblogic      | CVE-2017-10271   | unSerialize  | POST     | Weblogic XMLDecoder deSerialization                        |
| Oracle Weblogic      | CVE-2019-2725    | unSerialize  | POST     | Weblogic wls9_async deSerialization                        |
| Oracle Weblogic      | CVE-2020-14750   | unAuth       | GET      | Weblogic Authentication bypass                             |
| Oracle Weblogic      | CVE-2020-14882   | RCE          | GET      | Weblogic Unauthorized command execution                    |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Webmin               | CVE-2019-15107   | RCE          | POST     | Webmin Pre-Auth Remote code execution                      |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
| Yonyou               | CNVD-2021-30167  | RCE          | GET      | Yonyou-NC BeanShell Remote code execution                  |
| Yonyou               | None             | FileRead     | GET      | Yonyou-ERP-NC NCFindWeb Directory traversal                |
+----------------------+------------------+--------------+----------+------------------------------------------------------------+
```
</details>

## Code of conduct
Before using this tool, ensure that your actions comply with local laws and regulations and that you have obtained relevant authorization.

This tool is only for enterprises and individuals with legal authorization and is intended to enhance cyberspace security.

If you commit any illegal acts or cause any serious consequences during the use of the tool, you shall bear the corresponding liabilities by yourself, and we will not assume any legal and joint liability.

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
Usage: python3 vulcat.py <options>
Examples:
python3 vulcat.py -u https://www.example.com/
python3 vulcat.py -u https://www.example.com/ -a thinkphp --log 3
python3 vulcat.py -u https://www.example.com/ -a tomcat -v CVE-2017-12615
python3 vulcat.py -f url.txt -t 10
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
    --http-proxy=HTTP_PROXY
                        The HTTP/HTTPS proxy (e.g. --http-proxy
                        127.0.0.1:8080)
    --user-agent=UA     Customize the User-Agent
    --cookie=COOKIE     Add a cookie
    --log=LOG           The log level, Optional 1-6 (default: 1) [level 2:
                        Framework name + Vulnerability number + status code]
                        [level 3: Level 2 content + request method + request
                        target +POST data] [level 4: Level 2 content + request
                        packet] [Level 5: Level 4 content + response header]
                        [level 6: Level 5 content + response content]

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

  Api:
    The third party Api

    --dns=DNS           DNS platform, auxiliary verification without echo
                        vulnerability. dnslog.cn/ceye.io (optional parameter:
                        dnslog/ceye e.g. --dns ceye) (automatically selected
                        by default, ceye is preferred, and dnglog is
                        automatically changed when ceye is unavailable)

  Save:
    Save scan results

    --output-text=TXT_FILENAME
                        Save the scan results in TXT format, no vulnerability
                        will not generate files(e.g. --output-text result.txt)
    --output-json=JSON_FILENAME
                        Save the scan results in JSON format, no vulnerability
                        will not generate files(e.g. --output-text
                        result.json)

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
    AliDruid,nacos,airflow,apisix,flink,solr,struts2,tomcat,appweb,conflue
    nce,cisco,django,drupal,elasticsearch,f5bigip,fastjson,jenkins,keycloa
    k,nodered,showdoc,spring,thinkphp,ueditor,weblogic,webmin,yonyou
```

## language
You can change the language of -h/--help, currently only Chinese and English

* Open the vulcat/lib/initial/language.py
* Switching the "return" order and then saving the file implements the -h/--help language switch

```
def language():
    return lang['zh_cn']
    return lang['en_us']
```

## Dnslog
You can customize http://ceye.io

* Open the vulcat/lib/initial/config.py
* Find the code below, fill in your domain name and token, and save the file
```
args.ceye_domain = ''
args.ceye_token = ''
```

## Custom POC
* How do I write my own vulnerability POC and add it to vulcat
* Find vulcat/payloads/demo.py, which is a POC template in Vulcat (semi-finished) and requires the user to fill in the rest of the code

* **Modify the steps:**
1. Make a copy of demo.py and save it to prevent template loss. Then change the name of the POC (such as test.py)

2. Then follow the tips in demo.py to fill in your own code and introduce POC into vulcat

## Thanks
* [vulmap](https://github.com/zhzyker/vulmap)
* [sqlmap](https://github.com/sqlmapproject/sqlmap)
* [dirsearch](https://github.com/maurosoria/dirsearch)