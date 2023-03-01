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

        6. Weblogic LDAP 远程代码执行漏洞
            CVE-2021-2109
                Payload: http://wiki.peiqi.tech/wiki/webserver/Weblogic/Weblogic%20LDAP%20%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E%20CVE-2021-2109.html
                         https://www.freebuf.com/vuls/261710.html
                         https://github.com/WhiteHSBG/JNDIExploit/

'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Weblogic.cve_2014_4210 import cve_2014_4210_scan
from payloads.Weblogic.cve_2017_10271 import cve_2017_10271_scan
from payloads.Weblogic.cve_2019_2725 import cve_2019_2725_scan
from payloads.Weblogic.cve_2020_14750 import cve_2020_14750_scan
from payloads.Weblogic.cve_2020_14882 import cve_2020_14882_scan
from payloads.Weblogic.cve_2021_2109 import cve_2021_2109_scan

class Weblogic():
    def __init__(self):
        self.app_name = 'Weblogic'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2014_4210_scan, clients=clients),
            thread(target=cve_2017_10271_scan, clients=clients),
            thread(target=cve_2019_2725_scan, clients=clients),
            thread(target=cve_2020_14750_scan, clients=clients),
            thread(target=cve_2020_14882_scan, clients=clients),
            thread(target=cve_2021_2109_scan, clients=clients),
        ]

weblogic = Weblogic()
