#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    语言:
        -h/--help的英文
        -h/--help的中文
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
            'thread': 'The number of threads (default: 3)',
            'delay': 'Delay time/s (default: 0.5)',
            'timeout': 'Timeout/s (default: 10)',
            'http_proxy': 'The HTTP/HTTPS proxy (e.g. --http-proxy 127.0.0.1:8080)',
            'user_agent': 'Customize the User-Agent',
            'log': 'The log level, Optional 1-3 (default: 1)'
        },
        'application_help': {
            'title': 'Application',
            'name': 'Specify the target type for the scan',
            'application': 'Specifies the target type, separated by commas (e.g. thinkphp / thinkphp,weblogic) (default: all)'
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
            'name': 'AliDruid,cisco,thinkphp,tomcat,nacos,spring,weblogic,yonyou'
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
            'log': '日志等级, 可选1-3 (默认: 1)'
        },
        'application_help': {
            'title': 'Application',
            'name': '指定扫描的目标类型',
            'application': '指定目标类型, 多个使用逗号分隔 (如: thinkphp 或者 thinkphp,weblogic) (默认为全部)'
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
            'name': 'AliDruid,cisco,thinkphp,tomcat,nacos,spring,weblogic,yonyou'
        }
    }
}
