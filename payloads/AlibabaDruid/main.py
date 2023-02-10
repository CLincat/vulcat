#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    AlibabaDruid扫描类: 
        druid 未授权访问
            暂无编号
'''

# from lib.initial.config import config
# from lib.tool.md5 import md5
from lib.tool.thread import thread
from payloads.AlibabaDruid.unauth import alibaba_druid_unauthorized_scan

class Druid():
    def __init__(self):
        self.app_name = 'AlibabaDruid'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.unauth_scan, clients=clients),
        ]

Druid.unauth_scan = alibaba_druid_unauthorized_scan

alidruid = Druid()