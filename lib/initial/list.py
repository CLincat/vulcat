#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import color
import sys

def list():
    ''' 显示漏洞列表 '''
    vul_num = 0
    vul_list = ''
    vul_list += '+' + ('-'*22) + '+' + ('-'*18) + '+' + ('-'*14) + '+' + ('-'*10) + '+' + ('-'*67) + '+\n'

    for vul in vul_info:
        for info in vul_info[vul]:
            vul_num += 1
            vul_list += '| {}|'.format(vul.ljust(21))
            vul_list += ' {}|'.format(info['vul_id'].ljust(17))
            vul_list += ' {}|'.format(info['type'].ljust(13))
            vul_list += ' {}|'.format(info['method'].ljust(9))
            vul_list += ' {}\t|'.format(info['description'].ljust(56))
            vul_list += '\n'
        vul_list += '+' + ('-'*22) + '+' + ('-'*18) + '+' + ('-'*14) + '+' + ('-'*10) + '+' + ('-'*67) + '+\n'

    print(color.cyan(vul_list + str(vul_num - 1)))
    # print(vul_num)
    sys.exit(0)

vul_info = {
    'Target': [
        {
            'vul_id': 'Vul_id',
            'type': 'Type',
            'method': 'Method',
            'description': 'Description\t'
        }
    ],
    'Alibaba Druid': [
        {
            'vul_id': 'None',
            'type': 'unAuth',
            'method': 'GET',
            'description': '阿里巴巴Druid未授权访问'
        }
    ],
    'Alibaba Nacos': [
        {
            'vul_id': 'CVE-2021-29441',
            'type': 'unAuth',
            'method': 'GET/POST',
            'description': '阿里巴巴Nacos未授权访问'
        }
    ],
    'Apache Airflow': [
        {
            'vul_id': 'CVE-2020-17526',
            'type': 'unAuth',
            'method': 'GET',
            'description': 'Airflow身份验证绕过'
        }
    ],
    'Apache APISIX': [
        {
            'vul_id': 'CVE-2020-13945',
            'type': 'unAuth',
            'method': 'GET',
            'description': 'Apache APISIX默认密钥'
        }
    ],
    'Apache Flink': [
        {
            'vul_id': 'CVE-2020-17519',
            'type': 'FileRead',
            'method': 'GET',
            'description': 'Flink目录遍历'
        }
    ],
    'Apache Solr': [
        {
            'vul_id': 'CVE-2021-27905',
            'type': 'SSRF',
            'method': 'GET/POST',
            'description': 'Solr SSRF/任意文件读取'
        }
    ],
    'Apache Struts2': [
        {
            'vul_id': 'S2-001',
            'type': 'RCE',
            'method': 'POST',
            'description': 'Struts2远程代码执行'
        },
        {
            'vul_id': 'S2-005',
            'type': 'RCE',
            'method': 'GET',
            'description': 'Struts2远程代码执行'
        },
        {
            'vul_id': 'S2-007',
            'type': 'RCE',
            'method': 'GET',
            'description': 'Struts2远程代码执行'
        },
        {
            'vul_id': 'S2-008',
            'type': 'RCE',
            'method': 'GET',
            'description': 'Struts2远程代码执行'
        },
        {
            'vul_id': 'S2-009',
            'type': 'RCE',
            'method': 'GET',
            'description': 'Struts2远程代码执行'
        },
        {
            'vul_id': 'S2-012',
            'type': 'RCE',
            'method': 'GET',
            'description': 'Struts2远程代码执行'
        }
    ],
    'Apache Tomcat': [
        {
            'vul_id': 'CVE-2017-12615',
            'type': 'FileUpload',
            'method': 'PUT',
            'description': 'PUT方法任意文件写入'
        }
    ],
    'AppWeb': [
        {
            'vul_id': 'CVE-2018-8715',
            'type': 'unAuth',
            'method': 'GET',
            'description': 'AppWeb身份认证绕过'
        }
    ],
    'Atlassian Confluence': [
        {
            'vul_id': 'CVE-2015-8399',
            'type': 'FileRead',
            'method': 'GET',
            'description': 'Confluence任意文件包含'
        },
        {
            'vul_id': 'CVE-2019-3396',
            'type': 'RCE/FileRead',
            'method': 'POST',
            'description': 'Confluence路径遍历和命令执行'
        },
        {
            'vul_id': 'CVE-2021-26084',
            'type': 'RCE',
            'method': 'POST',
            'description': 'Confluence Webwork Pre-Auth OGNL表达式命令注入'
        },
        {
            'vul_id': 'CVE-2022-26134',
            'type': 'RCE',
            'method': 'GET',
            'description': 'Confluence远程代码执行'
        }
    ],
    'Cisco': [
        {
            'vul_id': 'CVE-2020-3580',
            'type': 'XSS',
            'method': 'POST',
            'description': '思科ASA/FTD XSS跨站脚本攻击'
        }
    ],
    'Django': [
        {
            'vul_id': 'CVE-2017-12794',
            'type': 'XSS',
            'method': 'GET',
            'description': 'debug page XSS跨站脚本攻击'
        },
        {
            'vul_id': 'CVE-2018-14574',
            'type': 'Redirect',
            'method': 'GET',
            'description': 'CommonMiddleware url重定向'
        },
        {
            'vul_id': 'CVE-2019-14234',
            'type': 'SQLinject',
            'method': 'GET',
            'description': 'JSONfield SQL注入'
        },
        {
            'vul_id': 'CVE-2020-9402',
            'type': 'SQLinject',
            'method': 'GET',
            'description': 'GIS SQL注入'
        },
        {
            'vul_id': 'CVE-2021-35042',
            'type': 'SQLinject',
            'method': 'GET',
            'description': 'QuerySet.order_by SQL注入'
        }
    ],
    'Drupal': [
        {
            'vul_id': 'CVE-2018-7600',
            'type': 'RCE',
            'method': 'POST',
            'description': 'Drupal Drupalgeddon 2 远程代码执行'
        }
    ],
    'ElasticSearch': [
        {
            'vul_id': 'CVE-2014-3120',
            'type': 'RCE',
            'method': 'POST',
            'description': 'ElasticSearch命令执行'
        },
        {
            'vul_id': 'CVE-2015-1427',
            'type': 'RCE',
            'method': 'POST',
            'description': 'ElasticSearch Groovy 沙盒绕过&&代码执行'
        },
        {
            'vul_id': 'CVE-2015-3337',
            'type': 'FileRead',
            'method': 'GET',
            'description': 'ElasticSearch 目录穿越'
        },
        {
            'vul_id': 'CVE-2015-5531',
            'type': 'FileRead',
            'method': 'PUT/GET',
            'description': 'ElasticSearch 目录穿越'
        },
    ],
    'F5 BIG-IP': [
        {
            'vul_id': 'CVE-2020-5902',
            'type': 'RCE',
            'method': 'GET',
            'description': 'BIG-IP远程代码执行'
        },
        {
            'vul_id': 'CVE-2022-1388',
            'type': 'unAuth',
            'method': 'POST',
            'description': 'BIG-IP身份认证绕过'
        }
    ],
    'Fastjson': [
        {
            'vul_id': 'CNVD-2017-02833',
            'type': 'unSerialize',
            'method': 'POST',
            'description': 'Fastjson <= 1.2.24 反序列化'
        },
        {
            'vul_id': 'CNVD-2019-22238',
            'type': 'unSerialize',
            'method': 'POST',
            'description': 'Fastjson <= 1.2.47 反序列化'
        }
    ],
    'Jenkins': [
        {
            'vul_id': 'CVE-2018-1000861',
            'type': 'RCE',
            'method': 'POST',
            'description': 'jenkins 远程命令执行'
        }
    ],
    'Keycloak': [
        {
            'vul_id': 'CVE-2020-10770',
            'type': 'SSRF',
            'method': 'GET',
            'description': '使用request_uri调用未经验证的URL'
        }
    ],
    # 'Kindeditor': [
    #     {
    #         'vul_id': 'CVE-2018-18950',
    #         'type': 'FileRead',
    #         'method': 'GET',
    #         'description': 'Kindeditor 目录遍历'
    #     }
    # ],
    'NodeRED': [
        {
            'vul_id': 'CVE-2021-3223',
            'type': 'FileRead',
            'method': 'GET',
            'description': 'Node-RED 任意文件读取'
        }
    ],
    'ShowDoc': [
        {
            'vul_id': 'CNVD-2020-26585',
            'type': 'FileUpload',
            'method': 'POST',
            'description': 'ShowDoc 任意文件上传'
        }
    ],
    'Spring': [
        {
            'vul_id': 'CVE-2020-5410',
            'type': 'FileRead',
            'method': 'GET',
            'description': 'Spring Cloud目录遍历'
        },
        {
            'vul_id': 'CVE-2021-21234',
            'type': 'FileRead',
            'method': 'GET',
            'description': 'Spring Boot目录遍历'
        },
        {
            'vul_id': 'CVE-2022-22947',
            'type': 'RCE',
            'method': 'POST',
            'description': 'Spring Cloud Gateway SpEl远程代码执行'
        },
        {
            'vul_id': 'CVE-2022-22963',
            'type': 'RCE',
            'method': 'POST',
            'description': 'Spring Cloud Function SpEL远程代码执行'
        },
        {
            'vul_id': 'CVE-2022-22965',
            'type': 'RCE',
            'method': 'GET/POST',
            'description': 'Spring Framework远程代码执行'
        }
    ],
    'ThinkPHP': [
        {
            'vul_id': 'CVE-2018-1002015',
            'type': 'RCE',
            'method': 'GET',
            'description': 'ThinkPHP5.x 远程代码执行'
        },
        {
            'vul_id': 'CNVD-2018-24942',
            'type': 'RCE',
            'method': 'GET',
            'description': '未开启强制路由导致RCE'
        },
        {
            'vul_id': 'CNNVD-201901-445',
            'type': 'RCE',
            'method': 'POST',
            'description': '核心类Request远程代码执行'
        },
        {
            'vul_id': 'None',
            'type': 'RCE',
            'method': 'GET',
            'description': 'ThinkPHP2.x 远程代码执行'
        },
        {
            'vul_id': 'None',
            'type': 'SQLinject',
            'method': 'GET',
            'description': 'ThinkPHP5 ids参数SQL注入'
        }
    ],
    'Ueditor': [
        {
            'vul_id': 'None',
            'type': 'SSRF',
            'method': 'GET',
            'description': 'Ueditor编辑器SSRF'
        }
    ],
    'Oracle Weblogic': [
        {
            'vul_id': 'CVE-2014-4210',
            'type': 'SSRF',
            'method': 'GET',
            'description': 'Weblogic 服务端请求伪造'
        },
        {
            'vul_id': 'CVE-2017-10271',
            'type': 'unSerialize',
            'method': 'POST',
            'description': 'Weblogic XMLDecoder反序列化'
        },
        {
            'vul_id': 'CVE-2019-2725',
            'type': 'unSerialize',
            'method': 'POST',
            'description': 'Weblogic wls9_async反序列化'
        },
        {
            'vul_id': 'CVE-2020-14750',
            'type': 'unAuth',
            'method': 'GET',
            'description': 'Weblogic 权限验证绕过'
        },
        {
            'vul_id': 'CVE-2020-14882',
            'type': 'RCE',
            'method': 'GET',
            'description': 'Weblogic 未授权命令执行'
        }
    ],
    'Webmin': [
        {
            'vul_id': 'CVE-2019-15107',
            'type': 'RCE',
            'method': 'POST',
            'description': 'Webmin Pre-Auth 远程代码执行'
        }
    ],
    'Yonyou': [
        {
            'vul_id': 'CNVD-2021-30167',
            'type': 'RCE',
            'method': 'GET',
            'description': '用友NC BeanShell远程命令执行'
        },
        {
            'vul_id': 'None',
            'type': 'FileRead',
            'method': 'GET',
            'description': '用友ERP-NC NCFindWeb目录遍历'
        }
    ]
}

# vul_list = '''
# +------------------------------+---------+---------+-------------------------------+
# | Target    | Vul_id           | Type    | Method  | Description                   |
# +-----------+------------------+---------+---------+-------------------------------+
# | Cisco     | CVE-2020-3580    | XSS     | POST    | 思科ASA/FTD软件XSS漏洞        |
# | ThinkPHP  | CNVD-2018-24942  | RCE     | GET     | 未开启强制路由RCE             |
# | ThinkPHP  | CNNVD-201901-445 | RCE     | POST    | 核心类Request远程代码执行     |
# | XXX       | CVE-XXX-XXX      | RCE     | GET     | XXXXXXX                       |
# +-----------+------------------+---------+---------+-------------------------------+
# | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX     |
# +--------------------------------------------------------------------------+
# '''