#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Webmin是一个基于Web的系统配置工具, 用于类Unix系统: https://www.webmin.com/
    Webmin扫描类: 
        1. Webmin Pre-Auth 远程代码执行
            CVE-2019-15107
                Payload: https://vulhub.org/#/environments/webmin/CVE-2019-15107/

        2. Webmin 远程代码执行
            CVE-2019-15642
                Payload: https://www.seebug.org/vuldb/ssvid-98065

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Webmin.cve_2019_15107 import cve_2019_15107_scan
from payloads.Webmin.cve_2019_15642 import cve_2019_15642_scan

class Webmin():
    def __init__(self):
        self.app_name = 'Webmin'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2019_15107_scan, clients=clients),
            thread(target=self.cve_2019_15642_scan, clients=clients)
        ]

Webmin.cve_2019_15107_scan = cve_2019_15107_scan
Webmin.cve_2019_15642_scan = cve_2019_15642_scan

webmin = Webmin()
