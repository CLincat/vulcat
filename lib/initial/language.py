#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    语言:
        vulcat的英文
        vulcat的中文
'''

def language():
    return lang['zh_cn']
    return lang['en_us']

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
            'http_proxy': 'The HTTP/HTTPS proxy (e.g. --http-proxy 127.0.0.1:8080)',
            'user_agent': 'Customize the User-Agent',
            'cookie': 'Add a cookie',
            'log': 'The log level, Optional 1-6 (default: 1) [level 2: Framework name + Vulnerability number + status code] [level 3: Level 2 content + request method + request target +POST data] [level 4: Level 2 content + request packet] [Level 5: Level 4 content + response header] [level 6: Level 5 content + response content]'
        },
        'application_help': {
            'title': 'Application',
            'name': 'Specify the target type for the scan',
            'application': 'Specifies the target type, for supported frameworks, see the tips at the bottom, separated by commas (e.g. thinkphp / thinkphp,weblogic) (default: auto)',
            'vuln': 'Specify the vulnerability number,With -a/--application to scan a single vulnerability,You can use --list to see the vulnerability number,vulnerabilities that do not have a vulnerability number are not supported.The number does not discriminate between sizes, and the symbol - and _ are acceptable (e.g. -a fastjson -v cnVD-2019-22238 or -a Tomcat -v CVE-2017_12615)'
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
            'name': 'AliDruid,nacos,airflow,apisix,flink,solr,struts2,tomcat,appweb,confluence,cisco,discuz,django,drupal,elasticsearch,f5bigip,fastjson,jenkins,keycloak,mongoexpress,nodejs,nodered,showdoc,spring,thinkphp,ueditor,weblogic,webmin,yonyou'
        },
        'core': {
            'start': {
                'start': '[INFO] Start scanning target ',
                'unable': '[WARN] Unable to connect to ',
                'url_error': '[WARN] The destination {} is incorrect and needs to start with http:// or https://',
                'no_poc': '[No-POC] Disable Vulnerability scanning'
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
            'http_proxy': 'http/https代理 (如: --http-proxy 127.0.0.1:8080)',
            'user_agent': '自定义User-Agent',
            'cookie': '添加cookie',
            'log': '日志等级, 可选1-6 (默认: 1) [日志2级: 框架名称+漏洞编号+状态码] [日志3级: 2级内容+请求方法+请求目标+POST数据] [日志4级: 2级内容+请求数据包] [日志5级: 4级内容+响应头] [日志6级: 5级内容+响应内容]'
        },
        'application_help': {
            'title': 'Application',
            'name': '指定扫描的目标类型',
            'application': '指定框架类型, 支持的框架可以参考最下面的提示信息, 多个使用逗号分隔 (如: thinkphp 或者 thinkphp,weblogic) (默认将启用指纹识别, 并使用相应POC, 如果未识别出框架则使用全部POC)',
            'vuln': '指定漏洞编号, 配合-a/--application对单个漏洞进行扫描, 可以使用--list查看漏洞编号, 没有漏洞编号的漏洞暂不支持, 编号不区分大小, 符号-和_皆可 (如: -a fastjson -v CNVD-2019-22238 或者 -a Tomcat -v cvE-2017_12615)'
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
            'name': 'AliDruid,nacos,airflow,apisix,flink,solr,struts2,tomcat,appweb,confluence,cisco,discuz,django,drupal,elasticsearch,f5bigip,fastjson,jenkins,keycloak,mongoexpress,nodejs,nodered,showdoc,spring,thinkphp,ueditor,weblogic,webmin,yonyou'
        },
        'core': {
            'start': {
                'start': '[INFO] 开始扫描目标 ',
                'unable': '[WARN] 无法连接到 ',
                'url_error': '[WARN] 目标{}好像不对哦, 需要以http://或https://开头',
                'no_poc': '[No-POC] 不进行漏洞扫描'
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
