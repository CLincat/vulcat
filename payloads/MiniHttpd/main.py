#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Mini_httpd是一个微型的Http服务器(约为Apache的90%) 广泛被各类IOT(路由器, 交换器, 摄像头等) 作为嵌入式服务器
    Mini_httpd扫描类: 
        mini_httpd 任意文件读取
            CVE-2018-18778
                Payload: https://vulhub.org/#/environments/mini_httpd/CVE-2018-18778/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.MiniHttpd.cve_2018_18778 import cve_2018_18778_scan

class MiniHttpd():
    def __init__(self):
        self.app_name = 'MiniHttpd'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2018_18778_scan, clients=clients)
        ]

MiniHttpd.cve_2018_18778_scan = cve_2018_18778_scan

minihttpd = MiniHttpd()
