#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Eclipse Jetty 是一个 Java Web 服务器和 Java Servlet 容器。 
    Jetty扫描类: 
        1. jetty 模糊路径信息泄露
            CVE-2021-28164
                Payload: https://vulhub.org/#/environments/jetty/CVE-2021-28164/

        2. jetty Utility Servlets ConcatServlet 双重解码信息泄露
            CVE-2021-28169
                Payload: https://vulhub.org/#/environments/jetty/CVE-2021-28169/

        3. jetty 模糊路径信息泄露
            CVE-2021-34429
                Payload: https://vulhub.org/#/environments/jetty/CVE-2021-34429/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Jetty.cve_2021_28164 import cve_2021_28164_scan
from payloads.Jetty.cve_2021_28169 import cve_2021_28169_scan
from payloads.Jetty.cve_2021_34429 import cve_2021_34429_scan

class Jetty():
    def __init__(self):
        self.app_name = 'Jetty'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2021_28164_scan, clients=clients),
            thread(target=self.cve_2021_28169_scan, clients=clients),
            thread(target=self.cve_2021_34429_scan, clients=clients)
        ]

Jetty.cve_2021_28164_scan = cve_2021_28164_scan
Jetty.cve_2021_28169_scan = cve_2021_28169_scan
Jetty.cve_2021_34429_scan = cve_2021_34429_scan

jetty = Jetty()
