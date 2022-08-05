# vulcat
除了代码写得有亿点点烂, BUG有亿点点多, 误报率有亿点点高, 等亿点点小问题以外，还是阔以的......吧

* vulcat可用于扫描web端漏洞(框架、中间件、CMS等), 发现漏洞时会提示目标url和payload, 使用者可以根据提示对漏洞进行手工验证<br/>
* 使用者还可以自己编写POC, 并添加到vulcat中进行扫描, 本项目也欢迎大家贡献自己的POC(白嫖)
* 如果有什么想法、建议或者遇到了BUG, 都可以issues

**目前支持扫描的web应用程序有:**
> AlibabaDruid, AlibabaNacos, ApacheAirflow, ApacheAPISIX, ApacheFlink, ApacheHadoop, ApacheSolr, ApacheStruts2, ApacheTomcat, AppWeb, AtlassianConfluence, Cicso, Discuz, Django, Drupal, ElasticSearch, F5-BIG-IP, Fastjson, Gitea, Gitlab, Grafana, Landray-OA, RubyOnRails, Jenkins, Keycloak, mongo-express, Node.js, NodeRED, ShowDoc, Spring, ThinkPHP, Ueditor, Weblogic, Webmin, Yonyou

<details>
<summary><strong>目前支持扫描的web漏洞有: [点击展开]</strong></summary>

```
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Target               | Vul_id             | Type         | Description                                                        |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Alibaba Druid        | None               | unAuth       | 阿里巴巴Druid未授权访问                                            |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Alibaba Nacos        | CVE-2021-29441     | unAuth       | 阿里巴巴Nacos未授权访问                                            |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Apache Airflow       | CVE-2020-17526     | unAuth       | Airflow身份验证绕过                                                |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Apache APISIX        | CVE-2020-13945     | unAuth       | Apache APISIX默认密钥                                              |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Apache Flink         | CVE-2020-17519     | FileRead     | Flink目录遍历                                                      |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Apache Hadoop        | None               | unAuth       | Hadoop YARN ResourceManager 未授权访问                             |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Apache Solr          | CVE-2021-27905     | SSRF         | Solr SSRF/任意文件读取                                             |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Apache Struts2       | S2-001             | RCE          | Struts2远程代码执行                                                |
| Apache Struts2       | S2-005             | RCE          | Struts2远程代码执行                                                |
| Apache Struts2       | S2-007             | RCE          | Struts2远程代码执行                                                |
| Apache Struts2       | S2-008             | RCE          | Struts2远程代码执行                                                |
| Apache Struts2       | S2-009             | RCE          | Struts2远程代码执行                                                |
| Apache Struts2       | S2-012             | RCE          | Struts2远程代码执行                                                |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Apache Tomcat        | CVE-2017-12615     | FileUpload   | PUT方法任意文件写入                                                |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| AppWeb               | CVE-2018-8715      | unAuth       | AppWeb身份认证绕过                                                 |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Atlassian Confluence | CVE-2015-8399      | FileRead     | Confluence任意文件包含                                             |
| Atlassian Confluence | CVE-2019-3396      | RCE/FileRead | Confluence路径遍历和命令执行                                       |
| Atlassian Confluence | CVE-2021-26084     | RCE          | Confluence Webwork Pre-Auth OGNL表达式命令注入                     |
| Atlassian Confluence | CVE-2022-26134     | RCE          | Confluence远程代码执行                                             |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Cisco                | CVE-2020-3580      | XSS          | 思科ASA/FTD XSS跨站脚本攻击                                        |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Discuz               | wooyun-2010-080723 | RCE          | 全局变量防御绕过RCE                                                |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Django               | CVE-2017-12794     | XSS          | debug page XSS跨站脚本攻击                                         |
| Django               | CVE-2018-14574     | Redirect     | CommonMiddleware url重定向                                         |
| Django               | CVE-2019-14234     | SQLinject    | JSONfield SQL注入                                                  |
| Django               | CVE-2020-9402      | SQLinject    | GIS SQL注入                                                        |
| Django               | CVE-2021-35042     | SQLinject    | QuerySet.order_by SQL注入                                          |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Drupal               | CVE-2014-3704      | SQLinject    | Drupal < 7.32 Drupalgeddon SQL 注入                                |
| Drupal               | CVE-2017-6920      | RCE          | Drupal Core 8 PECL YAML 反序列化代码执行                           |
| Drupal               | CVE-2018-7600      | RCE          | Drupal Drupalgeddon 2 远程代码执行                                 |
| Drupal               | CVE-2018-7602      | RCE          | Drupal 远程代码执行                                                |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| ElasticSearch        | CVE-2014-3120      | RCE          | ElasticSearch命令执行                                              |
| ElasticSearch        | CVE-2015-1427      | RCE          | ElasticSearch Groovy 沙盒绕过&&代码执行                            |
| ElasticSearch        | CVE-2015-3337      | FileRead     | ElasticSearch 目录穿越                                             |
| ElasticSearch        | CVE-2015-5531      | FileRead     | ElasticSearch 目录穿越                                             |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| F5 BIG-IP            | CVE-2020-5902      | RCE          | BIG-IP远程代码执行                                                 |
| F5 BIG-IP            | CVE-2022-1388      | unAuth       | BIG-IP身份认证绕过                                                 |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Fastjson             | CNVD-2017-02833    | unSerialize  | Fastjson <= 1.2.24 反序列化                                        |
| Fastjson             | CNVD-2019-22238    | unSerialize  | Fastjson <= 1.2.47 反序列化                                        |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Gitea                | None               | unAuth       | Gitea 1.4.0 未授权访问                                             |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Gitlab               | CVE-2021-22205     | RCE          | GitLab Pre-Auth 远程命令执行                                       |
| Gitlab               | CVE-2021-22214     | SSRF         | Gitlab CI Lint API未授权 SSRF                                      |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Grafana              | CVE-2021-43798     | FileRead     | Grafana 8.x 插件模块路径遍历                                       |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Jenkins              | CVE-2018-1000861   | RCE          | jenkins 远程命令执行                                               |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Keycloak             | CVE-2020-10770     | SSRF         | 使用request_uri调用未经验证的URL                                   |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Landray              | CNVD-2021-28277    | FileRead/SSRF| 蓝凌OA 任意文件读取/SSRF                                           |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| mongo-express        | CVE-2019-10758     | RCE          | 未授权远程代码执行                                                 |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Nodejs               | CVE-2017-14849     | FileRead     | Node.js目录穿越                                                    |
| Nodejs               | CVE-2021-21315     | RCE          | Node.js命令执行                                                    |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| NodeRED              | CVE-2021-3223      | FileRead     | Node-RED 任意文件读取                                              |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Ruby on Rails        | CVE-2018-3760      | FileRead     | Ruby on Rails 路径遍历                                             |
| Ruby on Rails        | CVE-2019-5418      | FileRead     | Ruby on Rails 任意文件读取                                         |
| Ruby on Rails        | CVE-2020-8163      | RCE          | Ruby on Rails 命令执行                                             |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| ShowDoc              | CNVD-2020-26585    | FileUpload   | ShowDoc 任意文件上传                                               |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Spring               | CVE-2020-5410      | FileRead     | Spring Cloud目录遍历                                               |
| Spring               | CVE-2021-21234     | FileRead     | Spring Boot目录遍历                                                |
| Spring               | CVE-2022-22947     | RCE          | Spring Cloud Gateway SpEl远程代码执行                              |
| Spring               | CVE-2022-22963     | RCE          | Spring Cloud Function SpEL远程代码执行                             |
| Spring               | CVE-2022-22965     | RCE          | Spring Framework远程代码执行                                       |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| ThinkPHP             | CVE-2018-1002015   | RCE          | ThinkPHP5.x 远程代码执行                                           |
| ThinkPHP             | CNVD-2018-24942    | RCE          | 未开启强制路由导致RCE                                              |
| ThinkPHP             | CNNVD-201901-445   | RCE          | 核心类Request远程代码执行                                          |
| ThinkPHP             | None               | RCE          | ThinkPHP2.x 远程代码执行                                           |
| ThinkPHP             | None               | SQLinject    | ThinkPHP5 ids参数SQL注入                                           |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Ueditor              | None               | SSRF         | Ueditor编辑器SSRF                                                  |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Oracle Weblogic      | CVE-2014-4210      | SSRF         | Weblogic 服务端请求伪造                                            |
| Oracle Weblogic      | CVE-2017-10271     | unSerialize  | Weblogic XMLDecoder反序列化                                        |
| Oracle Weblogic      | CVE-2019-2725      | unSerialize  | Weblogic wls9_async反序列化                                        |
| Oracle Weblogic      | CVE-2020-14750     | unAuth       | Weblogic 权限验证绕过                                              |
| Oracle Weblogic      | CVE-2020-14882     | RCE          | Weblogic 未授权命令执行                                            |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Webmin               | CVE-2019-15107     | RCE          | Webmin Pre-Auth 远程代码执行                                       |
| Webmin               | CVE-2019-15642     | RCE          | Webmin 远程代码执行                                                |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
| Yonyou               | CNNVD-201610-923   | SQLinject    | 用友GRP-U8 Proxy SQL注入                                           |
| Yonyou               | CNVD-2021-30167    | RCE          | 用友NC BeanShell远程命令执行                                       |
| Yonyou               | None               | FileRead     | 用友ERP-NC NCFindWeb目录遍历                                       |
| Yonyou               | None               | DSinfo       | 用友U8 OA getSessionList.jsp 敏感信息泄漏                          |
| Yonyou               | None               | SQLinject    | 用友U8 OA test.jsp SQL注入                                         |
+----------------------+--------------------+--------------+--------------------------------------------------------------------+
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
pip3 install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple
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
    指定扫描目标

    -u URL, --url=URL   单个url (如: -u http://www.baidu.com/)
    -f FILE, --file=FILE
                        含有多个url的文件, 一行一个 (如: -f url.txt)
    -r, --recursive     递归扫描url的每层目录

  Optional:
    可选功能选项

    -t THREAD, --thread=THREAD
                        线程数 (默认: 2)
    --delay=DELAY       延迟时间/秒 (默认: 1)
    --timeout=TIMEOUT   超时时间/秒 (默认: 10)
    --http-proxy=HTTP_PROXY
                        http/https代理 (如: --http-proxy 127.0.0.1:8080)
    --user-agent=UA     自定义User-Agent
    --cookie=COOKIE     添加cookie
    --log=LOG           日志等级, 可选1-6 (默认: 1) [日志2级: 框架名称+漏洞编号+状态码] [日志3级:
                        2级内容+请求方法+请求目标+POST数据] [日志4级: 2级内容+请求数据包] [日志5级:
                        4级内容+响应头] [日志6级: 5级内容+响应内容]

  Application:
    指定扫描的目标类型

    -a APPLICATION, --application=APPLICATION
                        指定框架类型, 支持的框架可以参考最下面的提示信息, 多个使用逗号分隔 (如: thinkphp 或者
                        thinkphp,weblogic) (默认将启用指纹识别, 并使用相应POC,
                        如果未识别出框架则使用全部POC)
    -v VULN, --vuln=VULN
                        指定漏洞编号, 配合-a/--application对单个漏洞进行扫描, 可以使用--list查看漏洞编号,
                        没有漏洞编号的漏洞暂不支持, 编号不区分大小, 符号-和_皆可 (如: -a fastjson -v
                        CNVD-2019-22238 或者 -a Tomcat -v cvE-2017_12615)

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

  General:
    通用工作参数

    --no-waf            禁用waf检测
    --no-poc            禁用安全漏洞扫描
    --batch             yes/no的选项不需要用户输入, 使用默认选项

  Lists:
    漏洞列表

    --list              查看所有Payload

  支持的目标类型(-a参数, 不区分大小写):
    AliDruid,nacos,airflow,apisix,flink,solr,struts2,tomcat,appweb,conflue
    nce,cisco,discuz,django,drupal,elasticsearch,f5bigip,fastjson,jenkins,
    keycloak,mongoexpress,nodejs,nodered,showdoc,spring,thinkphp,ueditor,w
    eblogic,webmin,yonyou
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