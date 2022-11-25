#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests

def unauth_scan(self, url):
    ''' 如果管理员没有为Jupyter Notebook配置密码, 将导致未授权访问, 
        游客可在其中创建一个console并执行任意Python代码和命令
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'unAuthorized'
    vul_info['vul_id'] = 'jupyter-unauthorized'
    vul_info['vul_method'] = 'GET'

    for payload in self.jupyter_unauthorized_payloads:
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
                verify=False
            )

            logger.logging(vul_info, res.status_code, res)                        # * LOG

            if ((('<body class="terminal-app' in res.text)
                    and ('data-ws-path="terminals/websocket/0"' in res.text)
                    and ('terminal/js/main.min.js' in res.text))
                or (('data-terminals-available="True"' in res.text)
                    and ('li role="presentation" id="new-terminal"' in res.text))
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results
        except requests.ConnectTimeout:
            logger.logging(vul_info, 'Timeout')
            return None
        except requests.ConnectionError:
            logger.logging(vul_info, 'Faild')
            return None
        except:
            logger.logging(vul_info, 'Error')
            return None
