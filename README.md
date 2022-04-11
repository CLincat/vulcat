# vulcat
除了代码写得有亿点点烂，等亿点点小问题以外，还是阔以的......吧

* vulcat可用于扫描web端漏洞(框架、中间件、CMS等), 发现漏洞时会提示目标url和payload, 使用者可以根据提示对漏洞进行手工验证<br/>
* 使用者还可以自己编写POC, 并添加到vulcat中进行扫描, 本项目也欢迎大家贡献自己的POC(白嫖)
* 如果有什么想法、建议或者遇到了BUG, 都可以issues

**目前支持扫描的web应用程序有:**
> AlibabaDruid, AlibabaNacos, ApacheTomcat, Cicso, Spring, ThinkPHP, Weblogic, Yonyou

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
| ApacheTomcat  | CVE-2017-12615   | WriteFile  | PUT      | PUT方法任意文件写入                                          |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Cisco         | CVE-2020-3580    | XSS        | POST     | 思科ASA/FTD软件跨站脚本攻击                                  |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Spring        | CVE-2022-22965   | RCE        | POST     | Spring Framework远程代码执行                                |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| ThinkPHP      | CNVD-2018-24942  | RCE        | GET      | 未开启强制路由导致RCE                                        |
| ThinkPHP      | CNNVD-201901-445 | RCE        | POST     | 核心类Request远程代码执行                                    |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Weblogic      | CVE-2020-14750   | unAuth     | GET      | Weblogic权限验证绕过                                        |
+---------------+------------------+------------+----------+------------------------------------------------------------+
| Yonyou        | CNVD-2021-30167  | RCE        | GET      | 用友NC BeanShell远程命令执行                                |
| Yonyou        | None             | FileRead   | GET      | 用友ERP-NC NCFindWeb接口任意文件读取/下载                    |
+---------------+------------------+------------+----------+------------------------------------------------------------+
```
</details>

## Installation & Usage
工具基于python3开发, 推荐使用python3.8及以上版本

* Git: `git clone https://github.com/starcat_l/vulcat.git`
* Zip: [点我](https://github.com/starcat_l/vulcat.zip)

```
git clone https://github.com/starcat_l/vulcat.git
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
    AliDruid,cisco,thinkphp,tomcat,nacos,spring,weblogic,yonyou
```

## language
可以修改-h/--help的语言, 目前只有中文和英文(麻麻再也不用担心我看不懂啦!)

* 打开vulcat/lib/initial/language.py
* en_us为英文, zh_cn为中文, 将return调换顺序, 然后保存文件就实现了-h语言的切换
![English](images/language.png)

## Custom POC
* 如何编写自己的漏洞POC, 并添加到vulcat中
* 找到vulcat/payloads/demo.py, demo.py是vulcat中的POC模板(半成品), 需要使用者填写剩余的代码
* **修改步骤:**
1. 先将demo.py复制一份并保存, 防止模板丢失, 然后修改文件名为POC的名字(如ThinkPHP.py), 名字可以自定义
![custom_1](images/custom_1.png)
2. 修改文件开头的注释, 具体修改如下↓
![custom_2](images/custom_2.png)
3. 根据代码旁边的提示, 修改相应内容↓
![custom_3_1](images/custom_3_1.png)
如果payloads有多个, 则添加多个path和data
![custom_3_2](images/custom_3_2.png)
4. 根据提示, 修改相应内容↓
![custom_4_1](images/custom_4_1.png)
![custom_4_2](images/custom_4_2.png)
5. 修改相应内容↓
![custom_5_1](images/custom_5_1.png)
![custom_5_2](images/custom_5_2.png)
6. 修改↓
![custom_6_1](images/custom_6_1.png)
![custom_6_2](images/custom_6_2.png)
7. 打开vulcat/lib/initial/config.py, 并添加应用程序的名字(注意: 名称要一样, 见下图↓)
![custom_7_1](images/custom_7_1.png)
![custom_7_2](images/custom_7_2.png)
8. 打开vulcat/lib/core/coreScan.py, 导入你的POC, 至此, vulcat就可以使用你的POC了, 你现在可以运行vulcat.py试试POC的效果
![custom_8](images/custom_8.png)
9. 如果你想在-h/--help中显示你的POC的应用程序名称, 打开vulcat/lib/initial/language.py, 找到以下代码并继续添加即可↓
![custom_9_1](images/custom_9_1.png)
![custom_9_2](images/custom_9_2.png)

## Thanks
感谢以下开源项目提供的灵感以及部分源代码
* [vulmap](https://github.com/zhzyker/vulmap)
* [sqlmap](https://github.com/sqlmapproject/sqlmap)
* [dirsearch](https://github.com/maurosoria/dirsearch)