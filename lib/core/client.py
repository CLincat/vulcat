#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.initial.config import config
from lib.tool.logger import logger
from lib.tool import head
from thirdparty import HackRequests
from thirdparty import requests
from time import sleep
import socket
import re

def create_headers(baseHeaders, headers, coverHeaders):
    ''' 创建Headers
        :param baseHeaders: 基础Headers
        :param headers: 要添加的Headers
        :param coverHeaders: 只使用该Headers
    '''
    
    if coverHeaders:
        new_headers = coverHeaders                          # * 覆盖基础Headers
    else:
        merge_headers = head.merge(baseHeaders, headers)    # * 基础Headers + 新Headers
        new_headers = merge_headers

    # * Nexus的CSRF Token (如果有的话)
    nexusCsrfToken = re.search(r'(NX-ANTI-CSRF-TOKEN=0\.\d*)|(NX-ANTI-CSRF-TOKEN=(\w|-){36})', str(baseHeaders))
    if (nexusCsrfToken):
        NX_ANTI_CSRF_TOKEN = nexusCsrfToken.group().split('=')
        new_headers['NX-ANTI-CSRF-TOKEN'] = NX_ANTI_CSRF_TOKEN[1]

    # * 如果没有指定User-Agent, 则使用基础User-Agent
    if not new_headers.get('User-Agent'):
        new_headers['User-Agent'] = baseHeaders.get('User-Agent', '')
    
    # * 如果没有指定Cookie, 并且有基础Cookie, 则添加基础Cookie
    if (not new_headers.get('Cookie')) and (baseHeaders.get('Cookie')):
        new_headers['Cookie'] = baseHeaders.get('Cookie', '')

    return new_headers

class RequestsClient():
    def __init__(
        self,
        base_url: str = None,
        verify: bool = False,
        timeout: float = 10,
        headers: dict = {},
        proxies: dict = None
    ):
        if (not base_url):
            logger.info('red_ex', '必须指定基础URL')
            raise Exception('You must input base URL')
        
        self.base_url = base_url
        self.verify = verify
        self.timeout = timeout
        self.headers = headers
        self.proxies = proxies
        self.domain = logger.get_domain(base_url)
        self.protocol_domain = logger.get_domain(base_url, protocol=True)
        
        self.delay = config.get('delay')

    def print_error_info(self, info):
        if info:
            logger.info(**info)

    def request(self, method, path, **kwargs):
        ''' requests.request中转 '''
        
        vul_info = kwargs.pop('vul_info', {'app_name': 'Test', 'vul_id': 'Test'})
        errors = kwargs.pop('errors', {})
        headers = kwargs.pop('headers', {})
        cover_headers = kwargs.pop('cover_headers', {})
        
        try:
            try:
                if self.base_url in path:                           # * 如果用户直接传递了完整URL
                    url = path                                      # * 则使用传递的URL
                else:
                    url = self.base_url + path                      # * 基础URL + 路径

                new_headers = create_headers(self.headers, headers, cover_headers)

                response = requests.request(
                    method,
                    url,
                    verify=self.verify,
                    timeout=self.timeout,
                    headers=new_headers,
                    proxies=self.proxies,
                    **kwargs
                )
                logger.logging(vul_info, response.status_code, response)    # * LOG

                sleep(self.delay)                                           # * 请求 与 请求之间的时间间隔/s

                return response
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                self.print_error_info(errors.get('Timeout'))
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                self.print_error_info(errors.get('Faild'))
                return None
            except KeyboardInterrupt:
                raise KeyboardInterrupt
            except:
                logger.logging(vul_info, 'Error')
                self.print_error_info(errors.get('Error'))
                return None
        except:
            logger.logging('Error', 'Error')
            return None

class HackRequestsClient():
    def __init__(
        self,
        base_url: str = None,
        timeout: float = 10,
        headers: dict = {},
        proxy: tuple = None,
        location: bool = False,
    ):
        if (not base_url):
            logger.info('red_ex', '必须指定基础URL')
            raise Exception('You must input base URL')
        
        self.base_url = base_url
        self.timeout = timeout
        self.headers = headers
        self.proxy = proxy
        self.location = location
        self.domain = logger.get_domain(base_url)
        self.protocol_domain = logger.get_domain(base_url, protocol=True)
        
        self.delay = config.get('delay')

    def print_error_info(self, info):
        if info:
            logger.info(**info)

    def request(self, method, path, **kwargs):
        ''' HackRequests.hackRequests.http中转 '''
        
        vul_info = kwargs.pop('vul_info', {'app_name': 'Test', 'vul_id': 'Test'})
        errors = kwargs.pop('errors', {})
        headers = kwargs.pop('headers', {})
        cover_headers = kwargs.pop('cover_headers', {})
        location = kwargs.pop('location', self.location)
        
        try:
            try:
                if self.base_url in path:                           # * 如果用户直接传递了完整URL
                    url = path                                      # * 则使用传递的URL
                else:
                    url = self.base_url + path                      # * 基础URL + 路径

                new_headers = create_headers(self.headers, headers, cover_headers)

                hack = HackRequests.hackRequests()
                response = hack.http(
                    url,
                    method=method,
                    timeout=self.timeout,
                    headers=new_headers,
                    proxy=self.proxy,
                    location=location,
                    **kwargs
                )
                logger.logging(vul_info, response.status_code, response)    # * LOG

                sleep(self.delay)                                           # * 请求 与 请求之间的时间间隔/s

                return response
            except socket.timeout:
                logger.logging(vul_info, 'Timeout')
                self.print_error_info(errors.get('Timeout'))
                return None
            except ConnectionRefusedError:
                logger.logging(vul_info, 'Faild')
                self.print_error_info(errors.get('Faild'))
                return None
            except KeyboardInterrupt:
                raise KeyboardInterrupt
            except:
                logger.logging(vul_info, 'Error')
                self.print_error_info(errors.get('Error'))
                return None
        except:
            logger.logging('Error', 'Error')
            return None
