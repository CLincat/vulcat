#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    语言:
        vulcat的英文
        vulcat的中文
'''

def language():
    return lang['en_us']  # * 默认英文
    return lang['zh_cn']  # * 上下换个位置就能切换语言

lang = {
    'en_us': {
        'target_help': {
            'title': 'Target',
            'name': 'Specify scan target',
            'url': 'A url (e.g. -u http://www.example.com/)',
            'file': 'A file containing multiple urls, one URL per line (e.g. -f url.txt)',
            'recursive': 'Recursively scan each directory of the URL'
        },
        'optional_help': {
            'title': 'Optional',
            'name': 'Optional function options',
            'thread': 'The number of threads (default: 2)',
            'delay': 'Delay time/s (default: 1)',
            'timeout': 'Timeout/s (default: 10)',
            'user_agent': 'Customize the User-Agent',
            'cookie': 'Add a cookie (e.g. --cookie "PHPSESSID=123456789")',
            'Authorization': 'Add a Authorization (e.g. --auth "Basic YWRtaW46YWRtaW4=")',
        },
        'log_help': {
            'title': 'Log',
            'name': 'Debug information',
            'log': 'The log level, Optional 1-6 (default: 1) [level 2: Framework name + Vulnerability number + status code] [level 3: Level 2 content + request method + request target +POST data] [level 4: Level 2 content + request packet] [Level 5: Level 4 content + response header] [level 6: Level 5 content + response content]'
        },
        'proxy_help': {
            'title': 'Proxy',
            'name': 'Proxy server',
            'http_proxy': 'The HTTP/HTTPS proxy (e.g. --http-proxy 127.0.0.1:8080)',
            'socks4_proxy': 'The socks4 proxy(e.g. --socks4-proxy 127.0.0.1:8080)',
            'socks5_proxy': 'The socks5 proxy(e.g. --socks5-proxy 127.0.0.1:8080 or admin:123456@127.0.0.1:8080)',

        },
        'application_help': {
            'title': 'Application',
            'name': 'Specify the target type for the scan',
            'application': 'Specifies the target type, for supported frameworks, see the tips at the bottom, separated by commas (e.g. thinkphp / thinkphp,weblogic) (default: auto)',
            'vuln': 'Specify the vulnerability number,With -a/--application to scan a single vulnerability,You can use --list to see the vulnerability number,vulnerabilities that do not have a vulnerability number are not supported.The number does not discriminate between sizes, and the symbol - and _ are acceptable (e.g. -a fastjson -v cnVD-2019-22238 or -a Tomcat -v CVE-2017_12615)',
            'exp': 'Use with the -a and -v parameters, After the Poc scan, if the vulnerability exists, enter the Exp interaction mode of the vulnerability; You can use --list to see Exp support vulnerabilities. (e.g. -a httpd -v CVE-2021-42013 -x)'
        },
        'api_help': {
            'title': 'Api',
            'name': 'The third party Api',
            'dns': 'DNS platform, auxiliary verification without echo vulnerability. dnslog.cn/ceye.io (optional parameter: dnslog/ceye e.g. --dns ceye) (automatically selected by default, ceye is preferred, and dnglog is automatically changed when ceye is unavailable)'
        },
        'save_help': {
            'title': 'Save',
            'name': 'Save scan results',
            'output_text': 'Save the scan results in TXT format, no vulnerability will not generate files(e.g. --output-text result.txt)',
            'output_json': 'Save the scan results in JSON format, no vulnerability will not generate files(e.g. --output-text result.json)'
        },
        'general_help': {
            'title': 'General',
            'name': 'General operating parameter',
            'no_waf': 'Disable WAF detection',
            'no_poc': 'Disable scanning for security vulnerabilities',
            'batch': 'The yes/no option does not require user input. The default option is used'
        },
        'lists_help': {
            'title': 'Lists',
            'name': 'Vulnerability list',
            'list': 'View all payload'
        },
        'app_list_help': {
            'title': 'Supported target types(Case insensitive)',
            'name': 'AliDruid, airflow, apisix, appweb, cisco, confluence, discuz, django, drupal, elasticsearch, f5bigip, fastjson, flink, gitea, gitlab, grafana, influxdb, hadoop, httpd, jenkins, jetty, jupyter, keycloak, landray, minihttpd, mongoexpress, nexus, nacos, nodejs, nodered, phpmyadmin, phpunit, rails, showdoc, solr, spring, supervisor, skywalking, thinkphp, tomcat, ueditor, weblogic, webmin, yonyou, zabbix'
        },
        'core': {
            'start': {
                'start': '[INFO] Start scanning target ',
                'unable': '[WARN] Unable to connect to ',
                'url_error': '[WARN] The destination {} is incorrect and needs to start with http:// or https://',
                'no_poc': '[No-POC] Disable Vulnerability scanning',
                'exp': 'When using -x/--exp, specify a vulnerability with -a and -v first(e.g. -a httpd -v cve-2021-41773 -x)'
            },
            'waf_finger': {
                'waf': '[INFO] The WAF detection for the current URL starts',
                'waf_find': '[INFO] {} is detected, Whether to continue scanning the current URL? - y(es)/N(o): ',
                'waf_not_find': '[INFO] Not found the WAF',
                'waf_timeout': '[-] WAF recognizes timeout and the target is not responding',
                'waf_conn_error': '[-] WAF recognition error, unable to connect to destination URL',
                'waf_error': '[-] WAF identification error, unknown error'

            },
            'web_finger': {
                'web': '[INFO] Fingerprint identification the current URL, please wait...',
                'web_find': '[INFO] Identify the framework{}',
                'web_not_find': '[INFO] No identification framework, all vulnerabilities will be scanned',
                'web_timeout': '[-] The framework recognizes a timeout and the target is not responding',
                'web_conn_error': '[-] Framework identification error, unable to connect to target URL',
                'web_error': '[-] Framework identification error, unknown error'

            },
            'addpoc': {
                'notfound': '[ERROR] The application not found: ',
                'error': '[ERROR] The addPOC is error',
                'vuln_error_1': '[ERROR] When using -v/--vuln, specify a frame name with -a/--application (e.g. -a tomcat -v CVE-2017-12615)',
                'vuln_error_2': '[ERROR] The specified framework or vulnerability number is incorrect'
            },
            'stop': {
                'continue': '[INFO] Continue to scan',
                'next': '[INFO] Skip current scan'
            },
            'end': {
                'wait': '[INFO] Wait for all threads to finish. Please wait...',
                'completed': '[INFO] Scan is completed'
            },
            'start_exp': {
                'lock': 'If you want to use -x/--exp, Please read the "vulcat/Exploit.lock" statement first, Delete the file with consent to the declaration, After the deletion, run -x/--exp again'
            }
        },
        'output': {
            'info': {
                'wait': '[INFO] Analyzing the results. Please wait...',
                'vul': '[+] Find vulnerable. A total of {} HTTP(s) requests:',
                'notvul': '[-] The target does not seem vulnerable. A total of {} HTTP(s) requests'
            },
            'text': {
                'success': '[INFO] The results have been saved to ',
                'faild': '[ERROR] Failed to save txt',
                'notvul': '[-] The result is not saved to '
            },
            'json': {
                'success': '[INFO] The results have been saved to ',
                'faild': '[ERROR] Failed to save json',
                'notvul': '[-] The result is not saved to '
            },
            'html': {
                'success': '[INFO] The results have been saved to ',
                'faild': '[ERROR] Failed to save html',
                'notvul': '[-] The result is not saved to '
            }
        }
    },
    'zh_cn': {
        'target_help': {
            'title': 'Target',
            'name': '指定扫描目标',
            'url': '单个url (如: -u http://www.baidu.com/)',
            'file': '含有多个url的文件, 一行一个 (如: -f url.txt)',
            'recursive': '递归扫描url的每层目录'
        },
        'optional_help': {
            'title': 'Optional',
            'name': '可选功能选项',
            'thread': '线程数 (默认: 2)',
            'delay': '延迟时间/秒 (默认: 1)',
            'timeout': '超时时间/秒 (默认: 10)',
            'user_agent': '自定义User-Agent',
            'cookie': '添加cookie (如: --cookie "PHPSESSID=123456789")',
            'Authorization': '添加Authorization (如: --auth "Basic YWRtaW46YWRtaW4=")'
        },
        'log_help': {
            'title': '日志',
            'name': '运行时输出的debug信息',
            'log': '日志等级, 可选1-6 (默认: 1) [日志2级: 框架名称+漏洞编号+状态码] [日志3级: 2级内容+请求方法+请求目标+POST数据] [日志4级: 2级内容+请求数据包] [日志5级: 4级内容+响应头] [日志6级: 5级内容+响应内容]'
        },
        'proxy_help': {
            'title': 'Proxy',
            'name': '代理',
            'http_proxy': 'http/https代理 (如: --http-proxy 127.0.0.1:8080)',
            'socks4_proxy': 'socks4代理(如: --socks4-proxy 127.0.0.1:8080)',
            'socks5_proxy': 'socks5代理(如: --socks5-proxy 127.0.0.1:8080 或 admin:123456@127.0.0.1:8080)',
        },
        'application_help': {
            'title': 'Application',
            'name': '指定扫描的目标类型',
            'application': '指定框架类型, 支持的框架可以参考最下面的提示信息, 多个使用逗号分隔 (如: thinkphp 或者 thinkphp,weblogic) (默认将启用指纹识别, 并使用相应POC, 如果未识别出框架则使用全部POC)',
            'vuln': '指定漏洞编号, 配合-a/--application对单个漏洞进行扫描, 可以使用--list查看漏洞编号, 没有漏洞编号的漏洞暂不支持, 编号不区分大小, 符号-和_皆可 (如: -a fastjson -v CNVD-2019-22238 或者 -a Tomcat -v cvE-2017_12615)',
            'exp': '配合-a和-v参数进行使用, Poc扫描过后, 如果该漏洞存在, 则进入该漏洞的Exp交互模式; 可以使用--list查看支持Exp的漏洞(如: -a httpd -v CVE-2021-42013 -x)'
        },
        'api_help': {
            'title': 'Api',
            'name': '第三方api',
            'dns': 'dns平台, 辅助无回显漏洞的验证, 支持dnslog.cn和ceye.io(可选参数: dnslog/ceye 如: --dns ceye) (默认自动选择, 优先ceye, ceye不可用时自动改为dnslog)'
        },
        'save_help': {
            'title': 'Save',
            'name': '保存扫描结果',
            'output_text': '以txt格式保存扫描结果, 无漏洞时不会生成文件(如: --output-text result.txt)',
            'output_json': '以json格式保存扫描结果, 无漏洞时不会生成文件(如: --output-text result.json)'
        },
        'general_help': {
            'title': 'General',
            'name': '通用工作参数',
            'no_waf': '禁用waf检测',
            'no_poc': '禁用安全漏洞扫描',
            'batch': 'yes/no的选项不需要用户输入, 使用默认选项'
        },
        'lists_help': {
            'title': 'Lists',
            'name': '漏洞列表',
            'list': '查看所有Payload'
        },
        'app_list_help': {
            'title': '支持的目标类型(-a参数, 不区分大小写)',
            'name': 'AliDruid, airflow, apisix, appweb, cisco, confluence, discuz, django, drupal, elasticsearch, f5bigip, fastjson, flink, gitea, gitlab, grafana, influxdb, hadoop, httpd, jenkins, jetty, jupyter, keycloak, landray, minihttpd, mongoexpress, nexus, nacos, nodejs, nodered, phpmyadmin, phpunit, rails, showdoc, solr, spring, supervisor, skywalking, thinkphp, tomcat, ueditor, weblogic, webmin, yonyou, zabbix'
        },
        'core': {
            'start': {
                'start': '[INFO] 开始扫描目标 ',
                'unable': '[WARN] 无法连接到 ',
                'url_error': '[WARN] 目标{}好像不对哦, 需要以http://或https://开头',
                'no_poc': '[No-POC] 不进行漏洞扫描',
                'exp': '使用-x/--exp时请先使用-a和-v指定一个漏洞, 例如-a httpd -v cve-2021-41773 -x'
            },
            'waf_finger': {
                'waf': '[INFO] 对当前url进行WAF检测, 请稍等...',
                'waf_find': '[INFO] 目标疑似存在{} 是否继续扫描当前url? - y(es)/N(o): ',
                'waf_not_find': '[INFO] 未发现WAF',
                'waf_timeout': '[-] WAF识别超时, 目标没有响应',
                'waf_conn_error': '[-] WAF识别出错, 无法连接至目标url',
                'waf_error': '[-] WAF识别出错, 未知错误'

            },
            'web_finger': {
                'web': '[INFO] 对当前url进行框架识别, 请稍等...',
                'web_find': '[INFO] 识别框架{}',
                'web_not_find': '[INFO] 未能识别框架, 将扫描全部漏洞',
                'web_timeout': '[-] 框架识别超时, 目标没有响应',
                'web_conn_error': '[-] 框架识别出错, 无法连接至目标url',
                'web_error': '[-] 框架识别出错, 未知错误'

            },
            'addpoc': {
                'notfound': '[ERROR] 未找到应用程序: ',
                'error': '[ERROR] 添加POC时出现错误',
                'vuln_error_1': '[ERROR] 使用-v/--vuln参数时, 请使用-a/--application指定1个框架名 (例如: -a tomcat -v CVE-2017-12615)',
                'vuln_error_2': '[ERROR] 指定的框架或漏洞编号有误'
            },
            'stop': {
                'continue': '[INFO] 继续扫描',
                'next': '[INFO] 跳过当前扫描'
            },
            'end': {
                'wait': '[INFO] 等待所有线程结束, 请稍等...',
                'completed': '[INFO] 扫描完成'
            },
            'start_exp': {
                'lock': '如果要使用-x/--exp, 请先阅读"vulcat/Exploit.lock"文件中的声明, 在同意声明的情况下删除该文件, 删除之后再次运行-x/--exp'
            }
        },
        'output': {
            'info': {
                'wait': '[INFO] 分析扫描结果中, 请稍等...',
                'vul': '[+] 发现漏洞, 共发送了{}个HTTP(s)请求:',
                'notvul': '[-] 未扫描出安全漏洞, 共发送了{}个HTTP(s)请求'
            },
            'text': {
                'success': '[INFO] 结果已经被保存到文件 ',
                'faild': '[ERROR] 保存txt文件失败',
                'notvul': '[-] 未保存结果至'
            },
            'json': {
                'success': '[INFO] 结果已经被保存到文件 ',
                'faild': '[ERROR] 保存json文件失败',
                'notvul': '[-] 未保存结果至'
            },
            'html': {
                'success': '[INFO] 结果已经被保存到文件 ',
                'faild': '[ERROR] 保存html文件失败',
                'notvul': '[-] 未保存结果至'
            }
        }
    }
}

lang['en_us']['disclaimer'] = '''By using this tool, you agree to the "Code of Conduct and Disclaimer" in "vulcat/README.md; If you do not agree, do not use this tool."\n\n\n'''
lang['zh_cn']['disclaimer'] = '''使用本工具, 代表您同意"vulcat/README.zh-cn.md"中的"行为规范和免责声明"; 如果您不同意, 请勿使用本工具\n\n\n'''

# * --list的中文
lang['zh_cn']['list'] = {
    'Alibaba Druid': '阿里巴巴Druid未授权访问',
    'Alibaba Nacos': {'CVE-2021-29441': '阿里巴巴Nacos未授权访问'},
    'Apache Airflow': {'CVE-2020-17526': 'Airflow身份验证绕过'},
    'Apache APISIX': {'CVE-2020-13945': 'Apache APISIX默认密钥',},
    'Apache Flink': {'CVE-2020-17519': 'Flink目录遍历',},
    'Apache Hadoop': 'Hadoop YARN ResourceManager 未授权访问',
    'Apache Httpd': {
        'CVE-2021-40438': 'Apache HTTP Server 2.4.48 mod_proxy SSRF                   ',
        'CVE-2021-41773': 'Apache HTTP Server 2.4.49 路径遍历',
        'CVE-2021-42013': 'Apache HTTP Server 2.4.50 路径遍历',
    },
    'Apache SkyWalking': {'CVE-2020-9483': 'SkyWalking SQL注入',},
    'Apache Solr': {
        'CVE-2017-12629': 'Solr 远程命令执行',
        'CVE-2019-17558': 'Solr Velocity 注入远程命令执行',
        'CVE-2021-27905': 'Solr SSRF/任意文件读取',
    },
    'Apache Tomcat': {'CVE-2017-12615': 'PUT方法任意文件写入',},
    'AppWeb': {'CVE-2018-8715': 'AppWeb身份认证绕过',},
    'Atlassian Confluence': {
        'CVE-2015-8399': 'Confluence任意文件包含',
        'CVE-2019-3396': 'Confluence路径遍历和命令执行',
        'CVE-2021-26084': 'Confluence Webwork Pre-Auth OGNL表达式命令注入',
        'CVE-2022-26134': 'Confluence远程代码执行',
    },
    'Cisco': {'CVE-2020-3580': '思科ASA/FTD XSS跨站脚本攻击',},
    'Discuz': {'wooyun-2010-080723': '全局变量防御绕过RCE',},
    'Django': {
        'CVE-2017-12794': 'debug page XSS跨站脚本攻击',
        'CVE-2018-14574': 'CommonMiddleware url重定向',
        'CVE-2019-14234': 'JSONfield SQL注入',
        'CVE-2020-9402': 'GIS SQL注入',
        'CVE-2021-35042': 'QuerySet.order_by SQL注入',
    },
    'Drupal': {
        'CVE-2014-3704': 'Drupal < 7.32 Drupalgeddon SQL 注入',
        'CVE-2017-6920': 'Drupal Core 8 PECL YAML 反序列化代码执行',
        'CVE-2018-7600': 'Drupal Drupalgeddon 2 远程代码执行',
        'CVE-2018-7602': 'Drupal 远程代码执行',
    },
    'ElasticSearch': {
        'CVE-2014-3120': 'ElasticSearch命令执行',
        'CVE-2015-1427': 'ElasticSearch Groovy 沙盒绕过&&代码执行',
        'CVE-2015-3337': 'ElasticSearch 目录穿越',
        'CVE-2015-5531': 'ElasticSearch 目录穿越',
    },
    'F5 BIG-IP': {
        'CVE-2020-5902': 'BIG-IP远程代码执行',
        'CVE-2022-1388': 'BIG-IP身份认证绕过',
    },
    'Fastjson': {
        'CNVD-2017-02833': 'Fastjson <= 1.2.24 反序列化',
        'CNVD-2019-22238': 'Fastjson <= 1.2.47 反序列化',
    },
    'Gitea': 'Gitea 1.4.0 未授权访问',
    'Gitlab': {
        'CVE-2021-22205': 'GitLab Pre-Auth 远程命令执行',
        'CVE-2021-22214': 'Gitlab CI Lint API未授权 SSRF',
    },
    'Grafana': {'CVE-2021-43798': 'Grafana 8.x 插件模块路径遍历',},
    'Influxdb': 'influxdb 未授权访问',
    'Jenkins': {'CVE-2018-1000861': 'jenkins 远程命令执行',},
    'Jetty': {
        'CVE-2021-28164': 'jetty 模糊路径信息泄露',
        'CVE-2021-28169': 'jetty Utility Servlets ConcatServlet 双重解码信息泄露',
        'CVE-2021-34429': 'jetty 模糊路径信息泄露',
    },
    'Jupyter': 'Jupyter 未授权访问',
    'Keycloak': {'CVE-2020-10770': '使用request_uri调用未经验证的URL',},
    'Landray': {'CNVD-2021-28277': '蓝凌OA 任意文件读取/SSRF',},
    'Mini Httpd': {'CVE-2018-18778': 'mini_httpd 任意文件读取',},
    'mongo-express': {'CVE-2019-10758': '未授权远程代码执行',},
    'Nexus Repository': {
        'CVE-2019-5475': '2.x yum插件 远程命令执行',
        'CVE-2019-7238': '3.x 远程命令执行',
        'CVE-2019-15588': '2019-5475的绕过',
        'CVE-2020-10199': '3.x 远程命令执行',
        'CVE-2020-10204': '3.x 远程命令执行',
    },
    'Nodejs': {
        'CVE-2017-14849': 'Node.js目录穿越',
        'CVE-2021-21315': 'Node.js命令执行',
    },
    'NodeRED': {'CVE-2021-3223': 'Node-RED 任意文件读取',},
    'phpMyadmin': {
        'WooYun-2016-199433': 'phpMyadmin Scripts/setup.php 反序列化',
        'CVE-2018-12613': 'phpMyadmin 4.8.1 远程文件包含',
    },
    'PHPUnit': {'CVE-2017-9841': 'PHPUnit 远程代码执行',},
    'Ruby on Rails': {
        'CVE-2018-3760': 'Ruby on Rails 路径遍历',
        'CVE-2019-5418': 'Ruby on Rails 任意文件读取',
        'CVE-2020-8163': 'Ruby on Rails 命令执行',
    },
    'ShowDoc': {'CNVD-2020-26585': 'ShowDoc 任意文件上传',},
    'Spring': {
        'CVE-2016-4977': 'Spring Security OAuth2 远程命令执行',
        'CVE-2017-8046': 'Spring Data Rest 远程命令执行',
        'CVE-2018-1273': 'Spring Data Commons 远程命令执行',
        'CVE-2020-5410': 'Spring Cloud目录遍历',
        'CVE-2021-21234': 'Spring Boot目录遍历',
        'CVE-2022-22947': 'Spring Cloud Gateway SpEl远程代码执行',
        'CVE-2022-22963': 'Spring Cloud Function SpEL远程代码执行',
        'CVE-2022-22965': 'Spring Framework远程代码执行',
    },
    'Supervisor': {
        'CVE-2017-11610': 'Supervisor 远程命令执行'
    },
    'ThinkPHP': {
        'CVE-2018-1002015': 'ThinkPHP5.x 远程代码执行',
        'CNVD-2018-24942': '未开启强制路由导致RCE',
        'CNNVD-201901-445': '核心类Request远程代码执行',
        '2.x RCE': 'ThinkPHP2.x 远程代码执行',
        '5 ids sqlinject': 'ThinkPHP5 ids参数SQL注入',
    },
    'Ueditor': 'Ueditor编辑器SSRF',
    'Oracle Weblogic': {
        'CVE-2014-4210': 'Weblogic 服务端请求伪造',
        'CVE-2017-10271': 'Weblogic XMLDecoder反序列化',
        'CVE-2019-2725': 'Weblogic wls9_async反序列化',
        'CVE-2020-14750': 'Weblogic 权限验证绕过',
        'CVE-2020-14882': 'Weblogic 未授权命令执行',
    },
    'Webmin': {
        'CVE-2019-15107': 'Webmin Pre-Auth 远程代码执行',
        'CVE-2019-15642': 'Webmin 远程代码执行',
    },
    'Yonyou': {
        'CNNVD-201610-923': '用友GRP-U8 Proxy SQL注入',
        'CNVD-2021-30167': '用友NC BeanShell远程命令执行',
        'NCFindWeb': '用友ERP-NC NCFindWeb目录遍历',
        'getSessionList.jsp': '用友U8 OA getSessionList.jsp 敏感信息泄漏',
        'test.jsp': '用友U8 OA test.jsp SQL注入',
    },
    'Zabbix': {
        'CVE-2016-10134': 'latest.php或jsrpc.php存在sql注入'
    }
}

# ! ------------------------------------------------------------

# * --list的英文
lang['en_us']['list'] = {
    'Alibaba Druid': 'Alibaba Druid unAuthorized',
    'Alibaba Nacos': {'CVE-2021-29441': 'Alibaba Nacos unAuthorized'},
    'Apache Airflow': {'CVE-2020-17526': 'Apache Airflow Authentication bypass'},
    'Apache APISIX': {'CVE-2020-13945': 'Apache APISIX default access token',},
    'Apache Flink': {'CVE-2020-17519': 'Apache Flink Directory traversal',},
    'Apache Hadoop': 'Apache Hadoop YARN ResourceManager unAuthorized',
    'Apache Httpd': {
        'CVE-2021-40438': 'Apache HTTP Server 2.4.48 mod_proxy SSRF',
        'CVE-2021-41773': 'Apache HTTP Server 2.4.49 Directory traversal',
        'CVE-2021-42013': 'Apache HTTP Server 2.4.50 Directory traversal',
    },
    'Apache SkyWalking': {'CVE-2020-9483': 'SkyWalking SQLinject',},
    'Apache Solr': {
        'CVE-2017-12629': 'Solr Remote code execution',
        'CVE-2019-17558': 'Solr RCE Via Velocity Custom Template',
        'CVE-2021-27905': 'Solr SSRF/FileRead',
    },
    'Apache Tomcat': {'CVE-2017-12615': 'Put method writes to any file',},
    'AppWeb': {'CVE-2018-8715': 'AppWeb Authentication bypass',},
    'Atlassian Confluence': {
        'CVE-2015-8399': 'Confluence any file include',
        'CVE-2019-3396': 'Confluence Directory traversal && RCE',
        'CVE-2021-26084': 'Confluence OGNL expression command injection',
        'CVE-2022-26134': 'Confluence Remote code execution',
    },
    'Cisco': {'CVE-2020-3580': 'Cisco ASA/FTD XSS',},
    'Discuz': {'wooyun-2010-080723': 'Remote code execution',},
    'Django': {
        'CVE-2017-12794': 'Django debug page XSS',
        'CVE-2018-14574': 'Django CommonMiddleware URL Redirect',
        'CVE-2019-14234': 'Django JSONfield SQLinject',
        'CVE-2020-9402': 'Django GIS SQLinject',
        'CVE-2021-35042': 'Django QuerySet.order_by SQLinject',
    },
    'Drupal': {
        'CVE-2014-3704': 'Drupal < 7.32 Drupalgeddon SQLinject',
        'CVE-2017-6920': 'Drupal Core 8 PECL YAML Remote code execution',
        'CVE-2018-7600': 'Drupal Drupalgeddon 2 Remote code execution',
        'CVE-2018-7602': 'Drupal Remote code execution',
    },
    'ElasticSearch': {
        'CVE-2014-3120': 'ElasticSearch Remote code execution',
        'CVE-2015-1427': 'ElasticSearch Groovy Sandbox to bypass && RCE',
        'CVE-2015-3337': 'ElasticSearch Directory traversal',
        'CVE-2015-5531': 'ElasticSearch Directory traversal',
    },
    'F5 BIG-IP': {
        'CVE-2020-5902': 'BIG-IP Remote code execution',
        'CVE-2022-1388': 'BIG-IP Authentication bypass',
    },
    'Fastjson': {
        'CNVD-2017-02833': 'Fastjson <= 1.2.24 deSerialization',
        'CNVD-2019-22238': 'Fastjson <= 1.2.47 deSerialization',
    },
    'Gitea': 'Gitea 1.4.0 unAuthorized',
    'Gitlab': {
        'CVE-2021-22205': 'GitLab Pre-Auth Remote code execution',
        'CVE-2021-22214': 'Gitlab CI Lint API SSRF',
    },
    'Grafana': {'CVE-2021-43798': 'Grafana 8.x Directory traversal',},
    'Influxdb': 'influxdb unAuthorized',
    'Jenkins': {'CVE-2018-1000861': 'jenkins Remote code execution',},
    'Jetty': {
        'CVE-2021-28164': 'jetty Disclosure information',
        'CVE-2021-28169': 'jetty Servlets ConcatServlet Disclosure information',
        'CVE-2021-34429': 'jetty Disclosure information',
    },
    'Jupyter': 'Jupyter unAuthorized',
    'Keycloak': {'CVE-2020-10770': 'request_uri SSRF',},
    'Landray': {'CNVD-2021-28277': 'Landray-OA FileRead/SSRF',},
    'Mini Httpd': {'CVE-2018-18778': 'mini_httpd FileRead',},
    'mongo-express': {'CVE-2019-10758': 'Remote code execution',},
    'Nexus Repository': {
        'CVE-2019-5475': '2.x yum Remote code execution',
        'CVE-2019-7238': '3.x Remote code execution',
        'CVE-2019-15588': '2019-5475 Bypass',
        'CVE-2020-10199': '3.x Remote code execution',
        'CVE-2020-10204': '3.x Remote code execution',
    },
    'Nodejs': {
        'CVE-2017-14849': 'Node.js Directory traversal',
        'CVE-2021-21315': 'Node.js Remote code execution',
    },
    'NodeRED': {'CVE-2021-3223': 'Node-RED Directory traversal',},
    'phpMyadmin': {
        'WooYun-2016-199433': 'phpMyadmin Scripts/setup.php Deserialization',
        'CVE-2018-12613': 'phpMyadmin 4.8.1 Remote File Inclusion',
    },
    'PHPUnit': {'CVE-2017-9841': 'PHPUnit Remote code execution',},
    'Ruby on Rails': {
        'CVE-2018-3760': 'Ruby on Rails Directory traversal',
        'CVE-2019-5418': 'Ruby on Rails FileRead',
        'CVE-2020-8163': 'Ruby on Rails Remote code execution',
    },
    'ShowDoc': {'CNVD-2020-26585': 'ShowDoc writes to any file',},
    'Spring': {
        'CVE-2016-4977': 'Spring Security OAuth2 Remote Command Execution',
        'CVE-2017-8046': 'Spring Data Rest Remote Command Execution',
        'CVE-2018-1273': 'Spring Data Commons Remote Command Execution',
        'CVE-2020-5410': 'Spring Cloud Directory traversal',
        'CVE-2021-21234': 'Spring Boot Directory traversal',
        'CVE-2022-22947': 'Spring Cloud Gateway SpEl Remote code execution',
        'CVE-2022-22963': 'Spring Cloud Function SpEL Remote code execution',
        'CVE-2022-22965': 'Spring Framework Remote code execution',
    },
    'Supervisor': {
        'CVE-2017-11610': 'Supervisor Remote Command Execution'
    },
    'ThinkPHP': {
        'CVE-2018-1002015': 'ThinkPHP5.x Remote code execution',
        'CNVD-2018-24942': 'The forced route is not enabled RCE',
        'CNNVD-201901-445': 'Core class Request Remote code execution',
        '2.x RCE': 'ThinkPHP2.x Remote code execution',
        '5 ids sqlinject': 'ThinkPHP5 ids SQLinject',
    },
    'Ueditor': 'Ueditor SSRF',
    'Oracle Weblogic': {
        'CVE-2014-4210': 'Weblogic SSRF',
        'CVE-2017-10271': 'Weblogic XMLDecoder deSerialization',
        'CVE-2019-2725': 'Weblogic wls9_async deSerialization',
        'CVE-2020-14750': 'Weblogic Authentication bypass',
        'CVE-2020-14882': 'Weblogic Unauthorized command execution',
    },
    'Webmin': {
        'CVE-2019-15107': 'Webmin Pre-Auth Remote code execution',
        'CVE-2019-15642': 'Webmin Remote code execution',
    },
    'Yonyou': {
        'CNNVD-201610-923': 'Yonyou-GRP-U8 Proxy SQLinject',
        'CNVD-2021-30167': 'Yonyou-NC BeanShell Remote code execution',
        'NCFindWeb': 'Yonyou-ERP-NC NCFindWeb Directory traversal',
        'getSessionList.jsp': 'Yonyou-U8-OA getSessionList.jsp Disclosure info',
        'test.jsp': 'Yonyou-U8-OA test.jsp SQLinject',
    },
    'Zabbix': {
        'CVE-2016-10134': 'latest.php or jsrpc.php SQLinject'
    }
}

# ! -x/--exp中文------------------------------------------------------------

lang['zh_cn']['exploit'] = {
    'identify': '[+] 识别为"{}"漏洞, 进入Exp交互模式:',
    'not_exp': '[-] 没有识别到漏洞类型, 或该漏洞类型不支持Exp',
    'not_request': '[-] POC结果没有返回Request(HTTP请求数据包), 无法使用Exp',
    'input_command': '根据漏洞类型 输入相应的内容(例如"whoami"或"/etc/passwd"): ',
    'not_command': '请输入命令 (可以输入“exit”退出)',
    'faild_command': '[Faild] 使用该命令时发生错误',
    'not_search_command': '[INFO] 替换新payload失败, 没有在旧的HTTP数据包中检测到旧的payload',
    'exit': '[INFO] 退出Exploit模式',
    'exp_faild': '[Exploit] 请求失败',
    'not_response': '没有检测到响应包中的回显内容',
    're_error': 'vcsearch语法错误: 错误的正则表达式',
}

# ! -x/--exp英文------------------------------------------------------------
lang['en_us']['exploit'] = {
    'identify': '[+] Identified as "{}" vulnerability, Enter the Exp interactive mode:',
    'not_exp': '[-] The vulnerability type is not identified, or Exp is not supported by the vulnerability type',
    'not_request': '[-] The poc result did not return the Request(HTTP Request), Unable to use Exp',
    'input_command': 'Enter the value according to the vulnerability type(e.g. "whoami"or"/etc/passwd"): ',
    'not_command': 'Please enter the command(You can enter "exit" to exit)',
    'faild_command': '[Faild] An error occurred while using the command',
    'not_search_command': '[INFO] Description Failed to replace the new payload, No old payload was detected in the old HTTP packet',
    'exit': '[INFO] Exit the Exploit.',
    'exp_faild': '[Exploit] Request failed',
    'not_response': 'Echoes in response packets are not detected',
    're_error': 'vcsearch syntax error: Incorrect regular expression',
}


