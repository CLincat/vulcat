#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    参数配置
'''

from thirdparty.requests import packages

global config

class Config():

    def __init__(self, args):
        # global global_args
        packages.urllib3.disable_warnings()                             # * requests忽略ssl证书警告

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
            if url[-1] != '/':                                          # * url最后的斜杠/
                url += '/'
            if args.recursive:                                          # * -r参数
                url_index = 8
                while url_index:
                    url_index = url.find('/', url_index)
                    url_index += 1
                    args.url_list.append(url[0:url_index])
                else:
                    del args.url_list[0]
                    del args.url_list[-1]
            else:
                del args.url_list[0]
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

        app_list = ['alidruid', 'cisco', 'django', 'thinkphp', 'tomcat', 'nacos', 'spring', 'weblogic', 'yonyou']
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
