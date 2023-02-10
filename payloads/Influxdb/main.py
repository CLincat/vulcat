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

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Influxdb.unauth import unauth_scan

class Influxdb():
    def __init__(self):
        self.app_name = 'influxdb'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.unauth_scan, clients=clients)
        ]

Influxdb.unauth_scan = unauth_scan

influxdb = Influxdb()
