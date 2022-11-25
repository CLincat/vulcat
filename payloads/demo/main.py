#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
XXX是一款...
    XXXXX扫描类: 
        XXXXX 未开启强制路由RCE
            CNVD-2018-24942
                Payload: https://xxx

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.thread import thread
from lib.tool import head
from payloads.demo.scan import 6_scan                   # ! 6: POC的名称

class 1():                                              # ! 1: 类名(例如 ThinkPHP)
    ''' 标有数字的地方都需要自己填写 '''
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = '2'                             # ! 2: 漏洞框架/应用程序/CMS等(例如 thinkphp)
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.3_payloads = [                             # ! 3: Payload的名称(例如 cnvd_2018_24942_payloads)
            {
                'path': '4',                            # ! 4: url路径(例如/admin/login)
                'data': '5'                             # ! 5: POST数据, 没有的话可以不写
            },
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.6_scan, url=url)                  # ! 6: 同上, POC的名称
        ]

1.6_scan = 6_scan                                                # ! 1/6: 同上, 类名/POC名称

12 = 1()                                                         # ! 1: 同上, 类名

'''
    # ! 12: 对象名称
    # ! 需要在vulcat/lib/initial/config.py加入对象名称, 找到以下代码并继续添加
                                                        app_list = ['alidruid', 'airflow', 'apisix', 'cisco', 'django', 'fastjson']
    # ! 然后在vulcat/lib/core/coreScan.py引入POC, 引入方式为
                                                        from payloads.文件名 import 对象名称
    # ! 引入完成后, 自定义POC就成功了, 可以运行vulcat试试效果
'''