#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    参数配置
'''

from lib.initial.language import language
from thirdparty.requests import packages
import re
import http.client

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

            
            if (url[-1] != '/') and ((re.search(r'(([0-9]{0,3})\.([0-9]{0,3})\.([0-9]{0,3})\.([0-9]{0,3}):([0-9]*))$', url)) or (not re.search(r'(.*\..*)$', url))): # * url的斜杠/(目录)
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
            args.headers['Cookie'] = args.cookie

        args.proxies = {
            'http': args.http_proxy,
            'https': args.http_proxy
        }

        app_list = ['alidruid', 'airflow', 'apisix', 'appweb', 'cisco', 'django', 'f5bigip', 'fastjson', 'flink', 'keycloak', 'nacos', 'solr', 'struts2', 'spring', 'thinkphp', 'tomcat', 'ueditor', 'weblogic', 'yonyou']
        if args.application == 'all':                                   # * -a参数
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
