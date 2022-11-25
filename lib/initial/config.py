#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    参数配置
'''

from lib.initial.language import language
from thirdparty.requests import packages
import re
import socket
import socks

global config

class Config():

    def __init__(self, args):
        packages.urllib3.disable_warnings()                             # * requests忽略ssl证书警告

        args.ceye_domain = ''                                           # * http://ceye.io/ 平台的域名
        args.ceye_token = ''                                            # * http://ceye.io/ 平台的token
        
        args.lang = language()                                          # * 语言

        args.url_list = []                                              # * url列表
        if args.url:
            args.url_list.append(args.url)
        elif args.file:
            f = open(args.file)
            urls = f.readlines()
            f.close()
            for url in urls:
                url = url.replace('\n', '')                             # * 文件中的换行符
                args.url_list.append(url)

        url_list_temp = args.url_list.copy()
        for url in url_list_temp:
            mark_index = url.find('?')
            if (mark_index + 1):
                url = url[:mark_index]
            del args.url_list[0]

            
            if (url[-1] != '/') and ((re.search(r'(([0-9]{0,3})\.([0-9]{0,3})\.([0-9]{0,3})\.([0-9]{0,3}):?([0-9]{0,5}))$', url)) or (not re.search(r'(.*\..*)$', url))): # * url的斜杠/(目录)
                url += '/'

            if args.recursive:                                          # * -r参数
                url = url.replace('//', 'This_is_a_placeholder', 1)
                dir_list = url.split('/')
                url = dir_list[0].replace('This_is_a_placeholder', '//', 1) + '/'
                del dir_list[0]
                args.url_list.append(url)

                for dir in range(len(dir_list)):
                    if ((dir_list[dir]) and (not re.search(r'(.*\..*)$', dir_list[dir]))):
                        url += dir_list[dir] + '/'
                        args.url_list.append(url)
                    else:
                        url += dir_list[dir]
                        if (url not in args.url_list):
                            args.url_list.append(url)
                        break
            else:
                args.url_list.append(url)

        args.headers = {
            'User-Agent': args.ua,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': '*/*',
            'Connection': 'close'
        }

        if args.cookie:
            args.headers['Cookie'] = args.cookie.lstrip('Cookie: ')

        if args.authorization:
            args.headers['Authorization'] = args.authorization.lstrip('Authorization: ')

        if args.http_proxy: # * requests代理
            args.proxies = {
                'http': 'http://' + args.http_proxy,
                'https': 'http://' + args.http_proxy
            }
            args.proxy = tuple(args.http_proxy.split(':')) # * HackRequests代理
        else:
            args.proxies = {}
            args.proxy = ()

        if args.socks5_proxy: # * socks 5
            if ('@' in args.socks5_proxy): # * 有无身份验证
                proxy_5 = args.socks5_proxy.replace('@', ':').split(':')
                socks.set_default_proxy(socks.SOCKS5, proxy_5[2], int(proxy_5[3]), username=proxy_5[0], password=proxy_5[1])
            else:
                proxy_5 = args.socks5_proxy.split(':')
                socks.set_default_proxy(socks.SOCKS5, proxy_5[0], int(proxy_5[1]))
            socket.socket = socks.socksocket

        elif args.socks4_proxy: # * socks 4
            proxy_4 = args.socks4_proxy.split(':')
            socks.set_default_proxy(socks.SOCKS4, proxy_4[0], int(proxy_4[1]))
            socket.socket = socks.socksocket

        if args.vuln:
            args.vuln = args.vuln.lower()
            args.vuln = args.vuln.replace('-', '_')
            args.vuln = args.vuln.replace('.', '_')

        app_list = [
            'alidruid', 'airflow', 'apisix', 'appweb', 
            'cisco', 'confluence', 
            'discuz', 'django', 'drupal',
            'elasticsearch', 
            'f5bigip', 'fastjson', 'flink', 
            'gitea', 'gitlab', # 'grafana', 
            'influxdb', 
            'hadoop', 'httpd', 
            'jenkins', 'jetty', 'jupyter', 
            'keycloak', # 'kindeditor',
            'landray', 
            'minihttpd', 'mongoexpress', 
            'nexus', 'nacos', 'nodejs', 'nodered', 
            'phpmyadmin', 'phpunit',
            'rails', 
            'showdoc', 'solr', 'spring', 'skywalking', 'supervisor',
            'thinkphp', 'tomcat', 
            'ueditor', 
            'weblogic', 'webmin',
            'yonyou',
            'zabbix'
        ]

        if args.application in ['auto', 'all']:                         # * -a参数
            args.app_list = app_list
        else:
            args.app_list = args.application.split(',')

        self.global_args = vars(args)                                   # * 转为字典

    def get(self, arg):
        return self.global_args[arg]

    def set(self, arg, value):
        self.global_args[arg] = value
        return

def config_init(args):
    ''' 参数初始化, 生成全局变量 '''
    global config
    config = Config(args)
