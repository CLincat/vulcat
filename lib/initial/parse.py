#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    参数接收
'''

from lib.initial.language import language
from optparse import OptionParser

def parse():
    ''' 参数列表 '''
    lang = language()           # * 帮助语言

    parser = OptionParser('\n' + lang['disclaimer'] + '''Usage: python3 vulcat.py <options>
Examples: 
python3 vulcat.py -h
python3 vulcat.py --list
python3 vulcat.py -u https://www.example.com/
python3 vulcat.py -f url.txt -o html
python3 vulcat.py -u https://www.example.com/ -v httpd --log 3
python3 vulcat.py -u https://www.example.com/ -v cnvd-2018-24942 --shell
''', version='vulcat.py-v2.0.0\n')
    # * 指定目标
    target = parser.add_option_group(lang['target_help']['title'], lang['target_help']['name'])
    target.add_option('-u', '--url', type='string', dest='url', default=None, help=lang['target_help']['url'])
    target.add_option('-f', '--file', type='string', dest='file', default=None, help=lang['target_help']['file'])
    target.add_option('-r', '--recursive', dest='recursive', action='store_true', help=lang['target_help']['recursive'])

    # * 可选参数
    optional = parser.add_option_group(lang['optional_help']['title'], lang['optional_help']['name'])
    optional.add_option('-t', '--thread', type='int', dest='thread', default=3, help=lang['optional_help']['thread'])
    optional.add_option('--delay', type='float', dest='delay', default=0.7, help=lang['optional_help']['delay'])
    optional.add_option('--timeout', type='float', dest='timeout', default=10, help=lang['optional_help']['timeout'])
    optional.add_option('--user-agent', type='string', dest='ua', default=None, help=lang['optional_help']['user_agent'])
    optional.add_option('--cookie', type='string', dest='cookie', default=None, help=lang['optional_help']['cookie'])
    optional.add_option('--auth', type='string', dest='authorization', default=None, help=lang['optional_help']['Authorization'])
    # optional.add_option('--random-ua', dest='random_ua', action='store_true', help='')

    # * 日志参数
    log = parser.add_option_group(lang['log_help']['title'], lang['log_help']['name'])
    log.add_option('--log', type='int', dest='log', default=1, help=lang['log_help']['log'])

    # * 代理
    proxy = parser.add_option_group(lang['proxy_help']['title'], lang['proxy_help']['name'])
    proxy.add_option('--http-proxy', type='string', dest='http_proxy', default=None, help=lang['proxy_help']['http_proxy'])
    proxy.add_option('--socks4-proxy', type='string', dest='socks4_proxy', default=None, help=lang['proxy_help']['socks4_proxy'])
    proxy.add_option('--socks5-proxy', type='string', dest='socks5_proxy', default=None, help=lang['proxy_help']['socks5_proxy'])

    # * 指定目标类型
    application = parser.add_option_group(lang['application_help']['title'], lang['application_help']['name'])
    # application.add_option('-a', '--application', type='string', dest='application', default='auto', help=lang['application_help']['application'])
    application.add_option('-v', '--vuln', type='string', dest='vuln', default=None, help=lang['application_help']['vuln'])
    application.add_option('--shell', dest='shell', action='store_true', help=lang['application_help']['shell'])
    application.add_option('--type', type='string', dest='vulnType', default=None, help=lang['application_help']['type'])

    # * 第三方api, 例如dnslog/ceye
    api = parser.add_option_group(lang['api_help']['title'], lang['api_help']['name'])
    # api.add_option('--dns', type='string', dest='dns', default='dnslog/ceye', help=lang['api_help']['dns'])
    api.add_option('--dns', dest='dns', default='auto', help=lang['api_help']['dns'], choices=['auto', 'dnslog-cn', 'dnslog-pw', 'ceye'])

    # * 保存扫描结果到文件中
    save = parser.add_option_group(lang['save_help']['title'], lang['save_help']['name'])
    save.add_option('-o', '--output', dest='output', default=None, help=lang['save_help']['output'], choices=['txt', 'json', 'html'])

    # * 通用参数
    general = parser.add_option_group(lang['general_help']['title'], lang['general_help']['name'])
    general.add_option('--no-waf', dest='no_waf', action='store_true', help=lang['general_help']['no_waf'])
    general.add_option('--no-poc', dest='no_poc', action='store_true', help=lang['general_help']['no_poc'])
    general.add_option('--batch', dest='batch', action='store_true', help=lang['general_help']['batch'])

    # * 查看漏洞列表
    lists = parser.add_option_group(lang['lists_help']['title'], lang['lists_help']['name'])
    lists.add_option('--list', dest='list', help=lang['lists_help']['list'], action='store_true')

    # app_list = parser.add_option_group(lang['app_list_help']['title'], lang['app_list_help']['name'])

    return parser.parse_args()