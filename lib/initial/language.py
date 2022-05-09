#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    语言:
        vulcat的英文
        vulcat的中文
'''

def language():
    return lang['en_us']
    return lang['zh_cn']

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
            'thread': 'The number of threads (default: 3)',
            'delay': 'Delay time/s (default: 0.5)',
            'timeout': 'Timeout/s (default: 10)',
            'http_proxy': 'The HTTP/HTTPS proxy (e.g. --http-proxy 127.0.0.1:8080)',
            'user_agent': 'Customize the User-Agent',
            'cookie': 'Add a cookie',
            'log': 'The log level, Optional 1-5 (default: 1) [level 2: Framework name + Vulnerability number + status code] [level 3: Level 2 content + request method + request target +POST data] [level 4: Level 2 content + request packet] [Level 5: Level 4 content + response header] [level 6: Level 5 content + response content]'
        },
        'application_help': {
            'title': 'Application',
            'name': 'Specify the target type for the scan',
            'application': 'Specifies the target type, separated by commas (e.g. thinkphp / thinkphp,weblogic) (default: all)'
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
        'lists_help': {
            'title': 'Lists',
            'name': 'Vulnerability list',
            'list': 'View all payload'
        },
        'app_list_help': {
            'title': 'Supported target types(Case insensitive)',
            'name': 'AliDruid,airflow,apisix,cisco,django,fastjson,flink,thinkphp,tomcat,nacos,spring,solr,struts2,weblogic,yonyou'
        },
        'core': {
            'start': {
                'start': '[INFO] Start scanning target ',
                'unable': '[WARN] Unable to connect to '
            },
            'addpoc': {
                'notfound': '[ERROR] The application not found: ',
                'error': '[ERROR] The addPOC is error'
            },
            'stop': {
                'continue': '[INFO] Continue to scan'
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
                'faild': '[ERROR] Failed to save txt'
            },
            'json': {
                'success': '[INFO] The results have been saved to ',
                'faild': '[ERROR] Failed to save json'
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
            'thread': '线程数 (默认: 3)',
            'delay': '延迟时间/秒 (默认: 0.5)',
            'timeout': '超时时间/秒 (默认: 10)',
            'http_proxy': 'http/https代理 (如: --http-proxy 127.0.0.1:8080)',
            'user_agent': '自定义User-Agent',
            'cookie': '添加cookie',
            'log': '日志等级, 可选1-5 (默认: 1) [日志2级: 框架名称+漏洞编号+状态码] [日志3级: 2级内容+请求方法+请求目标+POST数据] [日志4级: 2级内容+请求数据包] [日志5级: 4级内容+响应头] [日志6级: 5级内容+响应内容]'
        },
        'application_help': {
            'title': 'Application',
            'name': '指定扫描的目标类型',
            'application': '指定目标类型, 多个使用逗号分隔 (如: thinkphp 或者 thinkphp,weblogic) (默认为全部)'
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
        'lists_help': {
            'title': 'Lists',
            'name': '漏洞列表',
            'list': '查看所有Payload'
        },
        'app_list_help': {
            'title': '支持的目标类型(-a参数, 不区分大小写)',
            'name': 'AliDruid,airflow,apisix,cisco,django,fastjson,flink,thinkphp,tomcat,nacos,spring,solr,struts2,weblogic,yonyou'
        },
        'core': {
            'start': {
                'start': '[INFO] 开始扫描目标 ',
                'unable': '[WARN] 无法连接到 '
            },
            'addpoc': {
                'notfound': '[ERROR] 未找到应用程序: ',
                'error': '[ERROR] 添加POC时出现错误'
            },
            'stop': {
                'continue': '[INFO] 继续扫描'
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
                'notvul': '[-] 目标似乎没有漏洞, 共发送了{}个HTTP(s)请求'
            },
            'text': {
                'success': '[INFO] 结果已经被保存到 ',
                'faild': '[ERROR] 保存txt文件失败'
            },
            'json': {
                'success': '[INFO] 结果已经被保存到 ',
                'faild': '[ERROR] 保存json文件失败'
            }
        }
    }
}
