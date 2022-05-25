# vulcat
除了代码写得有亿点点烂, BUG有亿点点多, 误报率有亿点点高, 等亿点点小问题以外，还是阔以的......吧

* vulcat可用于扫描web端漏洞(框架、中间件、CMS等), 发现漏洞时会提示目标url和payload, 使用者可以根据提示对漏洞进行手工验证<br/>
* 使用者还可以自己编写POC, 并添加到vulcat中进行扫描, 本项目也欢迎大家贡献自己的POC(白嫖)
* 如果有什么想法、建议或者遇到了BUG, 都可以issues

**目前支持扫描的web应用程序有:**
> AlibabaDruid, AlibabaNacos, ApacheAirflow, ApacheAPISIX, ApacheFlink, ApacheSolr, ApacheStruts2, ApacheTomcat, AppWeb, Cicso, Django, F5-BIG-IP, Fastjson, Keycloak, Spring, ThinkPHP, Ueditor, Weblogic, Yonyou

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
| ApacheAPISIX  | CVE-2020-13945   | unAuth     | GET      | Apache APISIX默认密钥                                       |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ApacheFlink   | CVE-2020-17519   | FileRead   | GET      | Flink目录遍历                                               |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ApacheSolr    | CVE-2021-27905   | SSRF       | GET/POST | Solr SSRF/任意文件读取                                      |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ApacheStruts2 | S2-001           | RCE        | POST     | Struts2远程代码执行                                         |
| ApacheStruts2 | S2-005           | RCE        | GET      | Struts2远程代码执行                                         |
| ApacheStruts2 | S2-007           | RCE        | GET      | Struts2远程代码执行                                         |
| ApacheStruts2 | S2-008           | RCE        | GET      | Struts2远程代码执行                                         |
| ApacheStruts2 | S2-009           | RCE        | GET      | Struts2远程代码执行                                         |
| ApacheStruts2 | S2-012           | RCE        | GET      | Struts2远程代码执行                                         |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ApacheTomcat  | CVE-2017-12615   | FileUpload | PUT      | PUT方法任意文件写入                                          |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| AppWeb        | CVE-2018-8715    | unAuth     | GET      | AppWeb身份认证绕过                                          |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Cisco         | CVE-2020-3580    | XSS        | POST     | 思科ASA/FTD XSS跨站脚本攻击                                  |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Django        | CVE-2017-12794   | XSS        | GET      | Django debug page XSS跨站脚本攻击                           |
| Django        | CVE-2019-14234   | SQLinject  | GET      | Django JSONfield SQL注入                                   |
| Django        | CVE-2018-14574   | Redirect   | GET      | CommonMiddleware url重定向                                  |
| Django        | CVE-2020-9402    | SQLinject  | GET      | GIS SQL注入                                                |
| Django        | CVE-2021-35042   | SQLinject  | GET      | QuerySet.order_by SQL注入                                  |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| F5-BIG-IP     | CVE-2020-5902    | RCE        | GET      | BIG-IP远程代码执行                                          |
| F5-BIG-IP     | CVE-2022-1388    | unAuth     | POST     | BIG-IP身份认证绕过                                          |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Fastjson      | CNVD-2019-22238  | unSerialize| POST     | Fastjson <=1.2.47 反序列化                                  |
| Fastjson      | CVE-2017-18349   | unSerialize| POST     | Fastjson <= 1.2.24 反序列化                                 |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Keycloak      | CVE-2020-10770   | SSRF       | GET      | 使用request_uri调用未经验证的URL                             |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Spring        | CVE-2022-22965   | RCE        | GET/POST | Spring Framework远程代码执行                                |
| Spring        | CVE-2021-21234   | FileRead   | GET      | Spring Boot目录遍历                                         |
| Spring        | CVE-2020-5410    | FileRead   | GET      | Spring Cloud目录遍历                                        |
| Spring        | CVE-2022-22963   | RCE        | POST     | Spring Cloud Function SpEL远程代码执行                      |
| Spring        | CVE-2022-22947   | RCE        | POST     | Spring Cloud Gateway SpEl远程代码执行                       |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ThinkPHP      | CNVD-2018-24942  | RCE        | GET      | 未开启强制路由导致RCE                                        |
| ThinkPHP      | CNNVD-201901-445 | RCE        | POST     | 核心类Request远程代码执行                                    |
| ThinkPHP      | None             | RCE        | GET      | ThinkPHP2.x 远程代码执行                                    |
| ThinkPHP      | None             | RCE        | GET      | ThinkPHP5 ids参数SQL注入                                    |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Ueditor       | None             | SSRF       | GET      | Ueditor编辑器SSRF                                          |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Weblogic      | CVE-2020-14882   | RCE        | GET      | Weblogic未授权命令执行                                      |
| Weblogic      | CVE-2020-14750   | unAuth     | GET      | Weblogic权限验证绕过                                        |
| Weblogic      | CVE-2019-2725    | unSerialize| POST     | Weblogic wls9_async反序列化                                 |
| Weblogic      | CVE-2017-10271   | unSerialize| POST     | Weblogic XMLDecoder反序列化                                 |
| Weblogic      | CVE-2014-4210    | SSRF       | GET      | Weblogic 服务端请求伪造                                     |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Yonyou        | CNVD-2021-30167  | RCE        | GET      | 用友NC BeanShell远程命令执行                                |
| Yonyou        | None             | FileRead   | GET      | 用友ERP-NC NCFindWeb目录遍历                                |
+---------------+------------------+------------+----------+------------------------------------------------------------+
```
</details>

## Code of conduct
在使用本工具前, 请确保您的行为符合当地法律法规, 并且已经取得了相关授权。

本工具仅面向拥有合法授权的企业和个人等, 意在加强网络空间安全。

如果您在使用本工具的过程中存在任何非法行为, 或造成了任何严重后果, 您需自行承担相应责任, 我们将不承担任何法律及连带责任。


## Installation & Usage
工具基于python3开发, 推荐使用python3.8及以上版本

* Git: `git clone https://github.com/CLincat/vulcat.git`
* Zip: [点我](https://github.com/CLincat/vulcat/archive/refs/heads/main.zip)

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
    --log=LOG           日志等级, 可选1-5 (默认: 1) [日志2级: 框架名称+漏洞编号+状态码] [日志3级:
                        2级内容+请求方法+请求目标+POST数据] [日志4级: 2级内容+请求数据包] [日志5级:
                        4级内容+响应头] [日志6级: 5级内容+响应内容]

  Application:
    指定扫描的目标类型

    -a APPLICATION, --application=APPLICATION
                        指定目标类型, 多个使用逗号分隔 (如: thinkphp 或者 thinkphp,weblogic)
                        (默认为全部)

  Api:
    第三方api

    --dns=DNS           dns平台, 辅助无回显漏洞的验证, 支持dnslog.cn和ceye.io(可选参数:
                        dnslog/ceye 如: --dns ceye) (默认自动选择, 优先ceye,
                        ceye不可用时自动改为dnslog)

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
    AliDruid,airflow,apisix,appweb,cisco,django,f5bigip,fastjson,flink,key
    cloak,nacos,thinkphp,tomcat,spring,solr,struts2,ueditor,weblogic,yonyo
    u
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

## Dnslog
可以定义自己的http://ceye.io

* 打开vulcat/lib/initial/config.py
* 找到以下代码, 填写自己的域名和token, 保存文件即可
```
args.ceye_domain = ''
args.ceye_token = ''
```

## Custom POC
* 如何编写自己的漏洞POC, 并添加到vulcat中
* 找到vulcat/payloads/demo.py, demo.py是vulcat中的POC模板(半成品), 需要用户填写剩余的代码

* **修改步骤:**
1. 先将demo.py复制一份并保存, 防止模板丢失, 然后修改文件名为POC的名字(如test.py), 文件名可以自定义

2. 然后根据demo.py中的提示, 填写自己的代码, 并在vulcat中引入POC

## Thanks
感谢以下开源项目提供的灵感以及部分源代码
* [vulmap](https://github.com/zhzyker/vulmap)
* [sqlmap](https://github.com/sqlmapproject/sqlmap)
* [dirsearch](https://github.com/maurosoria/dirsearch)