# vulcat

* Vulcat can be used to scan for vulnerabilities on the Web side. When a vulnerability is discovered, the target URL and Payload are prompted. Users can manually verify the vulnerability according to the prompt<br/>
* Users can also write their own POC and add it to vulcat for scanning, You are also welcome to contribute your POC to the project
* If you have any ideas, suggestions, or bugs, you can issue

**Web applications that currently support scanning:**
> AlibabaDruid, AlibabaNacos, ApacheAirflow, ApacheFlink, ApacheSolr, ApacheStruts2, ApacheTomcat, Cicso, Django, Spring, ThinkPHP, Weblogic, Yonyou

<details>
<summary><b>The current web vulnerabilities that support scanning: [Click on]</b></summary>

```
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Target        | Vul_id           | Type       | Method   | Description                                                |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| AlibabaDruid  | None             | unAuth     | GET      | Alibaba Druid unAuthorized                                 |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| AlibabaNacos  | CVE-2021-29441   | unAuth     | GET/POST | Alibaba Nacos unAuthorized                                 |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ApacheAirflow | CVE-2020-17526   | unAuth     | GET      | Airflow Authentication bypass                              |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ApacheFlink   | CVE-2020-17519   | FileRead   | GET      | Flink Directory traversal                                  |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ApacheSolr    | CVE-2021-27905   | SSRF       | GET/POST | Solr SSRF/FileRead                                         |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ApacheStruts2 | S2-001           | RCE        | POST     | Struts2 Remote code execution                              |
| ApacheStruts2 | S2-005           | RCE        | GET      | Struts2 Remote code execution                              |
| ApacheStruts2 | S2-007           | RCE        | GET      | Struts2 Remote code execution                              |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ApacheTomcat  | CVE-2017-12615   | FileUpload | PUT      | Put method writes to any file                              |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Cisco         | CVE-2020-3580    | XSS        | POST     | Cisco ASA/FTD XSS                                          |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Django        | CVE-2017-12794   | XSS        | GET      | Django debug page XSS                                      |
| Django        | CVE-2019-14234   | SQLinject  | GET      | Django JSONfield SQLinject                                 |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Fastjson      | CNVD-2019-22238  | unSerialize| POST     | Fastjson <=1.2.47 deSerialization                          |
| Fastjson      | CVE-2017-18349   | unSerialize| POST     | Fastjson <= 1.2.24 deSerialization                         |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Spring        | CVE-2022-22965   | RCE        | POST     | Spring Framework Remote code execution                     |
| Spring        | CVE-2021-21234   | FileRead   | GET      | Spring Boot Directory traversal                            |
| Spring        | CVE-2020-5410    | FileRead   | GET      | Spring Cloud Directory traversal                           |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ThinkPHP      | CNVD-2018-24942  | RCE        | GET      | The forced route is not enabled Remote code execution      |
| ThinkPHP      | CNNVD-201901-445 | RCE        | POST     | Core class Request Remote code execution                   |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Weblogic      | CVE-2020-14882   | RCE        | GET      | Weblogic Unauthorized command execution                    |
| Weblogic      | CVE-2020-14750   | unAuth     | GET      | Weblogic Authentication bypass                             |
| Weblogic      | CVE-2019-2725    | unSerialize| POST     | Weblogic wls9_async deSerialization                        |
| Weblogic      | CVE-2017-10271   | unSerialize| POST     | Weblogic XMLDecoder deSerialization                        |
| Weblogic      | CVE-2014-4210    | SSRF       | GET      | Weblogic SSRF                                              |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Yonyou        | CNVD-2021-30167  | RCE        | GET      | Yonyou-NC BeanShell Remote code execution                  |
| Yonyou        | None             | FileRead   | GET      | Yonyou-ERP-NC NCFindWeb Directory traversal                |
+---------------+------------------+------------+----------+------------------------------------------------------------+
```
</details>

## Installation & Usage
The tool is developed based on python3. Python3.8 or later is recommended

* Git: `git clone https://github.com/CLincat/vulcat.git`
* Zip: [click me](https://github.com/CLincat/vulcat/archive/refs/heads/main.zip)

```
git clone https://github.com/CLincat/vulcat.git
cd vulcat
python3 vulcat.py -h
```
```
Usage: python3 vulcat.py <options>
Examples:
python3 vulcat.py -u https://www.example.com/
python3 vulcat.py -u https://www.example.com/ -a thinkphp --log 3
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
                        The number of threads (default: 3)
    --delay=DELAY       Delay time/s (default: 0.5)
    --timeout=TIMEOUT   Timeout/s (default: 10)
    --http-proxy=HTTP_PROXY
                        The HTTP/HTTPS proxy (e.g. --http-proxy
                        127.0.0.1:8080)
    --user-agent=UA     Customize the User-Agent
    --cookie=COOKIE     Add a cookie
    --log=LOG           The log level, Optional 1-3 (default: 1)

  Application:
    Specify the target type for the scan

    -a APPLICATION, --application=APPLICATION
                        Specifies the target type, separated by commas (e.g.
                        thinkphp / thinkphp,weblogic) (default: all)

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

  Lists:
    Vulnerability list

    --list              View all payload

  Supported target types(Case insensitive):
    AliDruid,airflow,cisco,django,fastjson,thinkphp,tomcat,nacos,spring,we
    blogic,yonyou
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

2. **Script description:** Modify the notes at the beginning of the file, and the scanned framework, vulnerability description, and vulnerability number of the script

```
#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    XXXXX扫描类: 
        XXXXX 未开启强制路由RCE
            CNVD-2018-24942
'''
```
3. **Class name**: frame name, and payload

```
class Demo():		   					 # ! Demo需要改为自定义的名称, 例如ABC(一般为框架名称, 例如ThinkPHP)
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = '!!!'                # ! 漏洞框架/应用程序/CMS名称等, 例如ThinkPHP
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.!!!_payloads = [                # ! 对应漏洞的Payload, 格式为: 漏洞编号_payloads, 例如cnvd_2018_24942_payloads
            {
                'path': '!!!',               # ! 漏洞的URL路径, 最前面没有斜杠/, 例如abc/qwe/index.php
                'data': '!!!'                # ! POST数据, 没有的话可以为空
            },
        ]

```
4. **Multiple payload:** You can add multiple dictionaries (path and data). Each dictionary corresponds to one payload, for example:

```
self.!!!_payloads = [
	{
	    'path': '',
	    'data': ''
	},
	{
	    'path': '',
	    'data': ''
	},
	{
	    'path': '',
	    'data': ''
	}
]
# ↑↑↑现在有3个payload
```
5. **Vulnerability information, request mode:** Define vulnerability information, headers, payload, requests (GET, POST, etc.)

```
    def !!!_scan(self, url):                            # ! POC的名称, 格式为: 漏洞编号_scan, 例如cnvd_2018_24942_scan
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = '!!!'                    # ! 漏洞类型
        vul_info['vul_id'] = '!!!'                      # ! 漏洞编号
        vul_info['vul_method'] = '!!!'                  # ! 请求方式
        vul_info['headers'] = {}                        # ! 如果该漏洞需要特殊的Headers,如User-Agent:Nacos-Server、Content-Type: text/xml之类的, 则需要填写, 没有的话为空

        headers = self.headers.copy()                   # * 复制一份headers, 防止污染全局headers
        headers.update(vul_info['headers'])

        for payload in self.!!!_payloads:               # ! Payload的名称, 就是在步骤3定义的payload
            path = payload['path']
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.!!!(                     # ! 请求方式, 根据你的漏洞来选择(get、post、put等)
                    target, 
                    timeout=self.timeout, 
                    headers=headers,                    # * 使用该漏洞的特殊Headers为headers, 使用正常的Headers为self.headers
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                vul_info['status_code'] = str(res.status_code)
                logger.logging(vul_info)
            except requests.ConnectTimeout:
                vul_info['status_code'] = 'Timeout'
                logger.logging(vul_info)
                return None
            except requests.ConnectionError:
                vul_info['status_code'] = 'Faild'
                logger.logging(vul_info)
                return None
```
6. **Results:** Information returned when vulnerabilities exist results: Vulnerability information and display format

```
'''
可以自定义results中的信息, 格式:
    标题: 值(str/list/dict)
        str类型: key: value的格式进行显示
        list类型: 会以key: value value value ...的格式进行显示
        dict类型: 会以↓的格式进行显示
                dict:
                    key1: value1
                    key2: value2
                    ...
'''

if ('!!!'):               # ! 判断扫描结果
    results = {
        'Target': target,
        'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
        'Method': vul_info['vul_method'],
        'Payload': {
            'Url': url,
            'Path': path
        }
    }
    return results
```
7. **Return the thread of the POC:**

```
def addscan(self, url):
        return [
            thread(target=self.!!!_scan, url=url)    # ! POC的名称, 就是步骤5定义的POC名称, 例如cnvd_2018_24942_scan
        ]

demo = Demo()										# ! 创建poc对象, xxx = 类名称, xxx可以自定义(一般为框架名称小写), 类名称就是步骤3中定义的名称
```
8. **POC is added in the configuration file:** open vulcat/lib/initial/config.py, and add the application name (note: shall be the same name, see below left)
![custom_7_1](images/custom_7_1.png)
![custom_7_2](images/custom_7_2.png)
9. **POC is added in the scanner:** open vulcat/lib/core/coreScan.py, import your POC, so far, vulcat can use your POC, you can now run the vulcat.py try out the effect of POC

```
from payloads.文件名 import xxx

# 文件名: 步骤1定义的文件名
# xxx: 同步骤8
```
10. If you want to display in -h/--help your POC application name, open the vulcat/lib/initial/language.py, find and can be left to continue to add the following code添加即可↓
![custom_9_1](images/custom_9_1.png)
![custom_9_2](images/custom_9_2.png)

## Thanks
* [vulmap](https://github.com/zhzyker/vulmap)
* [sqlmap](https://github.com/sqlmapproject/sqlmap)
* [dirsearch](https://github.com/maurosoria/dirsearch)