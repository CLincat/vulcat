#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import re

def get_form_token(client, path, vul_info):
    ''' 获取drupal的form_token '''
    
    res = client.request(
        'get',
        path,
        allow_redirects=False,
        vul_info=vul_info
    )
    if res is None:
        return None
    
    form_token = re.search(r'name="form_token" value=".{43}', res.text, re.I|re.M|re.U|re.S)
    if (form_token):
        token = form_token.group().replace('name="form_token" value="', '')
        return token
    else:
        return None
