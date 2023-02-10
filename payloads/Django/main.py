#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Django扫描类: 
        1. Django debug page XSS漏洞
            CVE-2017-12794
                Payload: https://vulhub.org/#/environments/django/CVE-2018-14574/

        2. Django JSONfield sql注入漏洞
            CVE-2019-14234
                Payload: https://vulhub.org/#/environments/django/CVE-2018-14574/
                         https://blog.csdn.net/weixin_42250835/article/details/121106792

        3. Django CommonMiddleware url重定向漏洞
            CVE-2018-14574
                Payload: https://vulhub.org/#/environments/django/CVE-2018-14574/

        4. Django GIS函数 sql注入漏洞
            CVE-2020-9402
                Payload: https://vulhub.org/#/environments/django/CVE-2020-9402/
        
        5. Django QuerySet.order_by sql注入漏洞
            CVE-2021-35042
                Payload: https://vulhub.org/#/environments/django/CVE-2021-35042/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Django.tool_get_urlconf import get_urlconf
from payloads.Django.cve_2017_12794 import cve_2017_12794_scan
from payloads.Django.cve_2018_14574 import cve_2018_14574_scan
from payloads.Django.cve_2019_14234 import cve_2019_14234_scan
from payloads.Django.cve_2020_9402 import cve_2020_9402_scan
from payloads.Django.cve_2021_35042 import cve_2021_35042_scan

class Django():
    def __init__(self):
        self.app_name = 'Django'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2017_12794_scan, clients=clients),
            thread(target=self.cve_2018_14574_scan, clients=clients),
            thread(target=self.cve_2019_14234_scan, clients=clients),
            thread(target=self.cve_2020_9402_scan, clients=clients),
            thread(target=self.cve_2021_35042_scan, clients=clients)
        ]

Django.get_urlconf = get_urlconf
Django.cve_2017_12794_scan = cve_2017_12794_scan
Django.cve_2018_14574_scan = cve_2018_14574_scan
Django.cve_2019_14234_scan = cve_2019_14234_scan
Django.cve_2020_9402_scan = cve_2020_9402_scan
Django.cve_2021_35042_scan = cve_2021_35042_scan

django = Django()