# vulcat
除了代码写得有亿点点烂, 误报率有亿点点高, 等亿点点小问题以外，还是阔以的......吧

* vulcat可用于扫描web端漏洞(框架、中间件、CMS等), 发现漏洞时会提示目标url和payload, 使用者可以根据提示对漏洞进行手工验证<br/>
* 使用者还可以自己编写POC, 并添加到vulcat中进行扫描, 本项目也欢迎大家贡献自己的POC(白嫖)
* 如果有什么想法、建议或者遇到了BUG, 都可以issues

**目前支持扫描的web应用程序有:**
> AlibabaDruid, AlibabaNacos, ApacheAirflow, ApacheStruts2, ApacheTomcat, Cicso, Django, Spring, ThinkPHP, Weblogic, Yonyou

<details>
<summary><b>目前支持扫描的web漏洞有: [点击展开]</b></summary>

```
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Target        | Vul_id           | Type       | Method   | Description                                                |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| AlibabaDruid  | None             | unAuth     | GET      | 阿里巴巴Druid未授权访问                                      |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| AlibabaNacos  | CVE-2021-29441   | unAuth     | GET/POST | 阿里巴巴Nacos未授权访问                                      |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ApacheAirflow | CVE-2020-17526   | unAuth     | GET      | Airflow身份验证绕过                                         |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ApacheStruts2 | S2-001           | RCE        | POST     | Struts2远程代码执行                                         |
| ApacheStruts2 | S2-005           | RCE        | GET      | Struts2远程代码执行                                         |
| ApacheStruts2 | S2-007           | RCE        | GET      | Struts2远程代码执行                                         |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ApacheTomcat  | CVE-2017-12615   | FileUpload | PUT      | PUT方法任意文件写入                                          |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Cisco         | CVE-2020-3580    | XSS        | POST     | 思科ASA/FTD XSS跨站脚本攻击                                  |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Django        | CVE-2017-12794   | XSS        | GET      | Django debug page XSS跨站脚本攻击                           |
| Django        | CVE-2019-14234   | SQLinject  | GET      | Django JSONfield SQL注入                                   |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Spring        | CVE-2022-22965   | RCE        | POST     | Spring Framework远程代码执行                                |
| Spring        | CVE-2021-21234   | FileRead   | GET      | Spring Boot目录遍历                                         |
| Spring        | CVE-2020-5410    | FileRead   | GET      | Spring Cloud目录遍历                                        |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ThinkPHP      | CNVD-2018-24942  | RCE        | GET      | 未开启强制路由导致RCE                                        |
| ThinkPHP      | CNNVD-201901-445 | RCE        | POST     | 核心类Request远程代码执行                                    |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Weblogic      | CVE-2020-14882   | RCE        | GET      | Weblogic未授权命令执行                                      |
| Weblogic      | CVE-2020-14750   | unAuth     | GET      | Weblogic权限验证绕过                                        |
| Weblogic      | CVE-2019-2725    | deSerializa| POST     | Weblogic wls9_async反序列化                                 |
| Weblogic      | CVE-2017-10271   | deSerializa| POST     | Weblogic XMLDecoder反序列化                                 |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Yonyou        | CNVD-2021-30167  | RCE        | GET      | 用友NC BeanShell远程命令执行                                |
| Yonyou        | None             | FileRead   | GET      | 用友ERP-NC NCFindWeb目录遍历                                |
+---------------+------------------+------------+----------+------------------------------------------------------------+
```
</details>

## Installation & Usage
工具基于python3开发, 推荐使用python3.8及以上版本

* Git: `git clone https://github.com/CLincat/vulcat.git`
* Zip: [点我](https://github.com/CLincat/vulcat/archive/refs/heads/main.zip)

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
    指定扫描目标

    -u URL, --url=URL   单个url (如: -u http://www.baidu.com/)
    -f FILE, --file=FILE
                        含有多个url的文件, 一行一个 (如: -f url.txt)
    -r, --recursive     递归扫描url的每层目录

  Optional:
    可选功能选项

    -t THREAD, --thread=THREAD
                        线程数 (默认: 3)
    --delay=DELAY       延迟时间/秒 (默认: 0.5)
    --timeout=TIMEOUT   超时时间/秒 (默认: 10)
    --http-proxy=HTTP_PROXY
                        http/https代理 (如: --http-proxy 127.0.0.1:8080)
    --user-agent=UA     自定义User-Agent
    --cookie=COOKIE     添加cookie
    --log=LOG           日志等级, 可选1-3 (默认: 1)

  Application:
    指定扫描的目标类型

    -a APPLICATION, --application=APPLICATION
                        指定目标类型, 多个使用逗号分隔 (如: thinkphp 或者 thinkphp,weblogic)
                        (默认为全部)

  Save:
    保存扫描结果

    --output-text=TXT_FILENAME
                        以txt格式保存扫描结果, 无漏洞时不会生成文件(如: --output-text result.txt)
    --output-json=JSON_FILENAME
                        以json格式保存扫描结果, 无漏洞时不会生成文件(如: --output-text
                        result.json)

  Lists:
    漏洞列表

    --list              查看所有Payload

  支持的目标类型(-a参数, 不区分大小写):
    AliDruid,cisco,django,thinkphp,tomcat,nacos,spring,weblogic,yonyou
```

## language
可以修改-h/--help的语言, 目前只有中文和英文(麻麻再也不用担心我看不懂啦!)

* 打开vulcat/lib/initial/language.py, 打开后会看到以下代码↓
* en_us为英文, zh_cn为中文, 将return调换上下顺序, 然后保存文件就实现了-h语言的切换
```
def language():
    return lang['zh_cn']
    return lang['en_us']
```

## Custom POC
* 如何编写自己的漏洞POC, 并添加到vulcat中
* 找到vulcat/payloads/demo.py, demo.py是vulcat中的POC模板(半成品), 需要用户填写剩余的代码
* **修改步骤:**
1. 先将demo.py复制一份并保存, 防止模板丢失, 然后修改文件名为POC的名字(如test.py), 名字可以自定义

2. **脚本描述:** 修改文件开头的注释, 该脚本扫描的框架、漏洞描述、漏洞编号等

```
#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    XXXXX扫描类: 
        XXXXX 未开启强制路由RCE
            CNVD-2018-24942
'''
```
3. **类名称、框架名称和payload:** 根据代码旁边的提示, 修改相应内容↓

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
4. **多个payload:** 可以添加多个字典(path和data), 1个字典对应1个payload, 例如:

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
5. **漏洞信息、请求方式:**定义漏洞信息、特殊headers、指定payload、requests请求方式(GET、POST等)

```
    def !!!_scan(self, url):                            # ! POC的名称, 格式为: 漏洞编号_scan, 例如cnvd_2018_24942_scan
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = '!!!'                    # ! 漏洞类型
        vul_info['vul_id'] = '!!!'                      # ! 漏洞编号
        vul_info['vul_method'] = '!!!'                  # ! 请求方式
        vul_info['headers'] = {}                        # ! 如果该漏洞需要特殊的Headers,如User-Agent:Nacos-Server、Content-Type: text/xml之类的, 则需要填写, 没有的话为空

        headers = self.headers
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
                    headers=headers, 
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
6. **存在漏洞时返回的信息results:** 漏洞信息、显示格式等

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
7. **返回该poc的线程:**

```
def addscan(self, url):
        return [
            thread(target=self.!!!_scan, url=url)    # ! POC的名称, 就是步骤5定义的POC名称, 例如cnvd_2018_24942_scan
        ]

demo = Demo()										# ! 创建poc对象, xxx = 类名称, xxx可以自定义(一般为框架名称小写), 类名称就是步骤3中定义的名称
```
8. **在配置文件中添加POC:** 打开vulcat/lib/initial/config.py, 并添加应用程序的名字(注意: 名称要一样, 见下图↓)
![custom_7_1](images/custom_7_1.png)
![custom_7_2](images/custom_7_2.png)
9. **在扫描器中添加POC:** 打开vulcat/lib/core/coreScan.py, 导入你的POC, 至此, vulcat就可以使用你的POC了, 你现在可以运行vulcat.py试试POC的效果

```
from payloads.文件名 import xxx

# 文件名: 步骤1定义的文件名
# xxx: 同步骤8
```
10. 如果你想在-h/--help中显示你的POC的应用程序名称, 打开vulcat/lib/initial/language.py, 找到以下代码并继续添加即可↓
![custom_9_1](images/custom_9_1.png)
![custom_9_2](images/custom_9_2.png)

## Thanks
感谢以下开源项目提供的灵感以及部分源代码
* [vulmap](https://github.com/zhzyker/vulmap)
* [sqlmap](https://github.com/sqlmapproject/sqlmap)
* [dirsearch](https://github.com/maurosoria/dirsearch)