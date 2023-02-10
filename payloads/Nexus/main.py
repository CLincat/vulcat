#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Nexus Repository Manager 3 是一款软件仓库, 可以用来存储和分发Maven、NuGET等软件源仓库
    Nexus扫描类: 
        1. Nexus Repository Manager 3 远程命令执行
            CVE-2019-7238
                Payload: https://vulhub.org/#/environments/nexus/CVE-2019-7238/
                         https://exp-blog.com/safe/cve/cve-2019-5475-lou-dong-fen-xi/#toc-heading-9
            
        2. Nexus Repository Manager 3 远程命令执行
            CVE-2020-10199
                Payload: https://vulhub.org/#/environments/nexus/CVE-2020-10199/
                         https://github.com/aleenzz/CVE-2020-10199

        3. Nexus Repository Manager 3 远程命令执行
            CVE-2020-10204
                Payload: https://vulhub.org/#/environments/nexus/CVE-2020-10204/
                         https://github.com/aleenzz/CVE-2020-10199

        4. Nexus Repository Manager 2 yum插件 远程命令执行
            CVE-2019-5475
                Payload: https://gitee.com/delete_user/CVE-2019-5475#0x60-cve-2019-15588%E9%9D%B6%E5%9C%BA%E9%AA%8C%E8%AF%81
                         https://cloud.tencent.com/developer/article/1655524

        5. Nexus Repository Manager 2 yum插件 二次远程命令执行
            CVE-2019-15588
                Payload: https://gitee.com/delete_user/CVE-2019-5475#0x60-cve-2019-15588%E9%9D%B6%E5%9C%BA%E9%AA%8C%E8%AF%81
                         https://cloud.tencent.com/developer/article/1655524

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Nexus.tool_get_yumid import get_yumID
from payloads.Nexus.cve_2019_5475 import cve_2019_5475_scan
from payloads.Nexus.cve_2019_7238 import cve_2019_7238_scan
from payloads.Nexus.cve_2019_15588 import cve_2019_15588_scan
from payloads.Nexus.cve_2020_10199 import cve_2020_10199_scan
from payloads.Nexus.cve_2020_10204 import cve_2020_10204_scan

class Nexus():
    def __init__(self):
        self.app_name = 'Nexus-Repository'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2019_15588_scan, clients=clients),
            thread(target=self.cve_2019_5475_scan, clients=clients),
            thread(target=self.cve_2019_7238_scan, clients=clients),
            thread(target=self.cve_2020_10199_scan, clients=clients),
            thread(target=self.cve_2020_10204_scan, clients=clients),
        ]

Nexus.get_yumID = get_yumID
Nexus.cve_2019_5475_scan = cve_2019_5475_scan
Nexus.cve_2019_7238_scan = cve_2019_7238_scan
Nexus.cve_2019_15588_scan = cve_2019_15588_scan
Nexus.cve_2020_10199_scan = cve_2020_10199_scan
Nexus.cve_2020_10204_scan = cve_2020_10204_scan

nexus = Nexus()
