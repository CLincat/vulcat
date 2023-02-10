#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Weblogic扫描类: 
        1. Weblogic 管理控制台未授权远程命令执行
            CVE-2020-14882
            
        2. Weblogic 权限验证绕过漏洞
            CVE-2020-14750
            
        3. Weblogic wls9_async_response 反序列化漏洞
            CVE-2019-2725
            
        4. Weblogic 'wls-wsat' XMLDecoder 反序列化漏洞
            CVE-2017-10271

        5. Weblogic 服务端请求伪造 (SSRF)
            CVE-2014-4210
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Weblogic.cve_2014_4210 import cve_2014_4210_scan
from payloads.Weblogic.cve_2017_10271 import cve_2017_10271_scan
from payloads.Weblogic.cve_2019_2725 import cve_2019_2725_scan
from payloads.Weblogic.cve_2020_14750 import cve_2020_14750_scan
from payloads.Weblogic.cve_2020_14882 import cve_2020_14882_scan

class Weblogic():
    def __init__(self):
        self.app_name = 'Weblogic'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2014_4210_scan, clients=clients),
            thread(target=self.cve_2017_10271_scan, clients=clients),
            thread(target=self.cve_2019_2725_scan, clients=clients),
            thread(target=self.cve_2020_14750_scan, clients=clients),
            thread(target=self.cve_2020_14882_scan, clients=clients),
        ]

Weblogic.cve_2014_4210_scan = cve_2014_4210_scan
Weblogic.cve_2017_10271_scan = cve_2017_10271_scan
Weblogic.cve_2019_2725_scan = cve_2019_2725_scan
Weblogic.cve_2020_14750_scan = cve_2020_14750_scan
Weblogic.cve_2020_14882_scan = cve_2020_14882_scan

weblogic = Weblogic()