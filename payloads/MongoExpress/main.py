#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
mongo-express是一款mongodb的第三方Web界面, 使用node和express开发
    Mongo-Express扫描类: 
        mongo-express 未授权远程代码执行
            CVE-2019-10758
                Payload: https://vulhub.org/#/environments/mongo-express/CVE-2019-10758/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.MongoExpress.cve_2019_10758 import cve_2019_10758_scan

class MongoExpress():
    def __init__(self):
        self.app_name = 'mongo-express'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2019_10758_scan, clients=clients)
        ]

mongoexpress = MongoExpress()
