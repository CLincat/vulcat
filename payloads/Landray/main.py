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

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Landray.cnvd_2021_28277 import cnvd_2021_28277_scan

class Landray():
    def __init__(self):
        self.app_name = 'Landray-OA'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cnvd_2021_28277_scan, clients=clients)
        ]

landray = Landray()
