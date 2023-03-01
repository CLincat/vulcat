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

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.RubyOnRails.cve_2018_3760 import cve_2018_3760_scan
from payloads.RubyOnRails.cve_2019_5418 import cve_2019_5418_scan
from payloads.RubyOnRails.cve_2020_8163 import cve_2020_8163_scan

class RubyOnRails():
    def __init__(self):
        self.app_name = 'Ruby on Rails'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2018_3760_scan, clients=clients),
            thread(target=cve_2019_5418_scan, clients=clients),
            thread(target=cve_2020_8163_scan, clients=clients)
        ]

rails = RubyOnRails()
