#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    AlibabaDruid扫描类: 
        druid 未授权访问
            暂无编号
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.thread import thread
from payloads.AlibabaDruid.unauth import alibaba_druid_unauthorized_scan

class Druid():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'AlibabaDruid'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.alibaba_druid_unauthorized_payloads = [
            {
                'path': 'druid/index.html',
                'data': ''
            }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.unauth_scan, url=url),
        ]

Druid.unauth_scan = alibaba_druid_unauthorized_scan

alidruid = Druid()