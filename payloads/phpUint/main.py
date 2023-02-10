#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
PHPUnit 是 PHP 语言中最常见的单元测试 (unit testing) 框架
    PHPUnit扫描类: 
        1. PHPUnit 远程代码执行
            CVE-2017-9841
                Payload: https://vulhub.org/#/environments/phpunit/CVE-2017-9841/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.phpUint.cve_2017_9841 import cve_2017_9841_scan

class phpUint():
    def __init__(self):
        self.app_name = 'phpUint'
        
    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2017_9841_scan, clients=clients)
        ]

phpUint.cve_2017_9841_scan = cve_2017_9841_scan

phpunit = phpUint()
