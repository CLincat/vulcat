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
from payloads.demo.scan import 6_scan                           # ! 6: POC的名称

class 1():                                                      # ! 1: 类名(例如 ThinkPHP)
    ''' 标有数字的地方都需要自己填写 '''
    def __init__(self):
        self.app_name = '2'                                     # ! 2: 漏洞框架/应用程序/CMS等(例如 thinkphp)

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=6_scan, clients=clients)              # ! 6: 同上, POC的名称
        ]

13 = 1()                                                        # ! 1: 同上, 类名

'''
    # ! 13: 对象名称
    # ! 在vulcat/config.yaml添加对象名称
    # ! 然后在vulcat/lib/core/coreScan.py引入POC, 引入方式为
                                                        from payloads.文件名 import 对象名称
    # ! 引入完成后, 自定义POC就成功了, 可以运行vulcat试试效果
'''