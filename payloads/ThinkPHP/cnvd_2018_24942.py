#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests

def cnvd_2018_24942_scan(self, url):
    ''' ThinkPHP5 未开启强制路由RCE'''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CNVD-2018-24942'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    headers = self.headers
    headers.update(vul_info['headers'])

    for payload in self.cnvd_2018_24942_payloads:   # * Payload
        path = payload['path']                      # * Path
        data = payload['data']                      # * Data
        target = url + path                         # * Target

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            res = requests.get(
                target, 
                timeout=self.timeout, 
                headers=headers, 
                data=data, 
                proxies=self.proxies, 
                verify=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG

            # * 判断扫描结果
            if (self.md in check.check_res(res.text, self.md) 
                or (('PHP Version' in res.text) 
                    and ('PHP License' in res.text))
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path
                    },
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
