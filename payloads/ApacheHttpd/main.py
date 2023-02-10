#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
httpd是Apache超文本传输协议(HTTP)服务器的主程序: https://httpd.apache.org/download.cgi
    Apache httpd扫描类: 
        1. Apache httpd 2.4.48 mod_proxy SSRF
            CVE-2021-40438
                Payload: https://vulhub.org/#/environments/httpd/CVE-2021-40438/

        2. Apache httpd 2.4.49 路径遍历
            CVE-2021-41773
                Payload: https://vulhub.org/#/environments/httpd/CVE-2021-41773/
                Paylaod: https://github.com/thehackersbrain/CVE-2021-41773/blob/main/exploit.py

        3. Apache HTTP Server 2.4.50 路径遍历
            CVE-2021-42013
                Payload: https://vulhub.org/#/environments/httpd/CVE-2021-42013/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.ApacheHttpd.cve_2021_40438 import cve_2021_40438_scan
from payloads.ApacheHttpd.cve_2021_41773 import cve_2021_41773_scan
from payloads.ApacheHttpd.cve_2021_42013 import cve_2021_42013_scan

class ApacheHttpd():
    def __init__(self):
        self.app_name = 'ApacheHttpd'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2021_40438_scan, clients=clients),
            thread(target=self.cve_2021_41773_scan, clients=clients),
            thread(target=self.cve_2021_42013_scan, clients=clients)
        ]

ApacheHttpd.cve_2021_40438_scan = cve_2021_40438_scan
ApacheHttpd.cve_2021_41773_scan = cve_2021_41773_scan
ApacheHttpd.cve_2021_42013_scan = cve_2021_42013_scan

httpd = ApacheHttpd()
