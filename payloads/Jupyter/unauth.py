#!/usr/bin/env python3
# -*- coding:utf-8 -*-

jupyter_unauthorized_payloads = [
    {'path': 'terminals/0'},
    {'path': '0'},
    {'path': ''},
]

def unauth_scan(self, clients):
    ''' 如果管理员没有为Jupyter Notebook配置密码, 将导致未授权访问, 
        游客可在其中创建一个console并执行任意Python代码和命令
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'unAuthorized',
        'vul_id': 'jupyter-unauthorized',
    }

    for payload in jupyter_unauthorized_payloads:
        path = payload['path']

        res = client.request(
            'get',
            path,
            vul_info=vul_info
        )
        if res is None:
            continue

        if ((('<body class="terminal-app' in res.text)
                and ('data-ws-path="terminals/websocket/0"' in res.text)
                and ('terminal/js/main.min.js' in res.text))
            or (('data-terminals-available="True"' in res.text)
                and ('li role="presentation" id="new-terminal"' in res.text))
        ):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
