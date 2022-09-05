#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import color
import sys

def list():
    ''' 显示漏洞列表 '''
    vul_num = 0
    vul_list = ''
    vul_list += '+' + ('-'*22) + '+' + ('-'*20) + '+' + ('-'*14) + '+' + ('-'*68) + '+\n'

    for vul in vul_info:
        for info in vul_info[vul]:
            vul_num += 1
            vul_list += '| {}|'.format(vul.ljust(21))
            vul_list += ' {}|'.format(info['vul_id'].ljust(19))
            vul_list += ' {}|'.format(info['type'].ljust(13))
            vul_list += ' {}\t|'.format(info['description'].ljust(57))
            vul_list += '\n'
        vul_list += '+' + ('-'*22) + '+' + ('-'*20) + '+' + ('-'*14) + '+' + ('-'*68) + '+\n'

    print(color.cyan(vul_list + str(vul_num - 1)))
    # print(vul_num)
    sys.exit(0)

vul_info = {
    'Target': [
        {
            'vul_id': 'Vul_id',
            'type': 'Type',
            'description': 'Description\t'
        }
    ],
    'Alibaba Druid': [
        {
            'vul_id': 'None',
            'type': 'unAuth',
            'description': '阿里巴巴Druid未授权访问'
        }
    ],
    'Alibaba Nacos': [
        {
            'vul_id': 'CVE-2021-29441',
            'type': 'unAuth',
            'description': '阿里巴巴Nacos未授权访问'
        }
    ],
    'Apache Airflow': [
        {
            'vul_id': 'CVE-2020-17526',
            'type': 'unAuth',
            'description': 'Airflow身份验证绕过'
        }
    ],
    'Apache APISIX': [
        {
            'vul_id': 'CVE-2020-13945',
            'type': 'unAuth',
            'description': 'Apache APISIX默认密钥'
        }
    ],
    'Apache Flink': [
        {
            'vul_id': 'CVE-2020-17519',
            'type': 'FileRead',
            'description': 'Flink目录遍历'
        }
    ],
    'Apache Hadoop': [
        {
            'vul_id': 'None',
            'type': 'unAuth',
            'description': 'Hadoop YARN ResourceManager 未授权访问'
        }
    ],
    'Apache Httpd': [
        {
            'vul_id': 'CVE-2021-40438',
            'type': 'SSRF',
            'description': 'Apache HTTP Server 2.4.48 mod_proxy SSRF                   '
        },
        {
            'vul_id': 'CVE-2021-41773',
            'type': 'FileRead/RCE',
            'description': 'Apache HTTP Server 2.4.49 路径遍历'
        },
        {
            'vul_id': 'CVE-2021-42013',
            'type': 'FileRead/RCE',
            'description': 'Apache HTTP Server 2.4.50 路径遍历'
        }
    ],
    'Apache Solr': [
        {
            'vul_id': 'CVE-2021-27905',
            'type': 'SSRF',
            'description': 'Solr SSRF/任意文件读取'
        }
    ],
    'Apache Struts2': [
        {
            'vul_id': 'S2-001',
            'type': 'RCE',
            'description': 'Struts2远程代码执行'
        },
        {
            'vul_id': 'S2-005',
            'type': 'RCE',
            'description': 'Struts2远程代码执行'
        },
        {
            'vul_id': 'S2-007',
            'type': 'RCE',
            'description': 'Struts2远程代码执行'
        },
        {
            'vul_id': 'S2-008',
            'type': 'RCE',
            'description': 'Struts2远程代码执行'
        },
        {
            'vul_id': 'S2-009',
            'type': 'RCE',
            'description': 'Struts2远程代码执行'
        },
        {
            'vul_id': 'S2-012',
            'type': 'RCE',
            'description': 'Struts2远程代码执行'
        }
    ],
    'Apache Tomcat': [
        {
            'vul_id': 'CVE-2017-12615',
            'type': 'FileUpload',
            'description': 'PUT方法任意文件写入'
        }
    ],
    'AppWeb': [
        {
            'vul_id': 'CVE-2018-8715',
            'type': 'unAuth',
            'description': 'AppWeb身份认证绕过'
        }
    ],
    'Atlassian Confluence': [
        {
            'vul_id': 'CVE-2015-8399',
            'type': 'FileRead',
            'description': 'Confluence任意文件包含'
        },
        {
            'vul_id': 'CVE-2019-3396',
            'type': 'RCE/FileRead',
            'description': 'Confluence路径遍历和命令执行'
        },
        {
            'vul_id': 'CVE-2021-26084',
            'type': 'RCE',
            'description': 'Confluence Webwork Pre-Auth OGNL表达式命令注入'
        },
        {
            'vul_id': 'CVE-2022-26134',
            'type': 'RCE',
            'description': 'Confluence远程代码执行'
        }
    ],
    'Cisco': [
        {
            'vul_id': 'CVE-2020-3580',
            'type': 'XSS',
            'description': '思科ASA/FTD XSS跨站脚本攻击'
        }
    ],
    'Discuz': [
        {
            'vul_id': 'wooyun-2010-080723',
            'type': 'RCE',
            'description': '全局变量防御绕过RCE'
        }
    ],
    'Django': [
        {
            'vul_id': 'CVE-2017-12794',
            'type': 'XSS',
            'description': 'debug page XSS跨站脚本攻击'
        },
        {
            'vul_id': 'CVE-2018-14574',
            'type': 'Redirect',
            'description': 'CommonMiddleware url重定向'
        },
        {
            'vul_id': 'CVE-2019-14234',
            'type': 'SQLinject',
            'description': 'JSONfield SQL注入'
        },
        {
            'vul_id': 'CVE-2020-9402',
            'type': 'SQLinject',
            'description': 'GIS SQL注入'
        },
        {
            'vul_id': 'CVE-2021-35042',
            'type': 'SQLinject',
            'description': 'QuerySet.order_by SQL注入'
        }
    ],
    'Drupal': [
        {
            'vul_id': 'CVE-2014-3704',
            'type': 'SQLinject',
            'description': 'Drupal < 7.32 Drupalgeddon SQL 注入'
        },
        {
            'vul_id': 'CVE-2017-6920',
            'type': 'RCE',
            'description': 'Drupal Core 8 PECL YAML 反序列化代码执行'
        },
        {
            'vul_id': 'CVE-2018-7600',
            'type': 'RCE',
            'description': 'Drupal Drupalgeddon 2 远程代码执行'
        },
        {
            'vul_id': 'CVE-2018-7602',
            'type': 'RCE',
            'description': 'Drupal 远程代码执行'
        }
    ],
    'ElasticSearch': [
        {
            'vul_id': 'CVE-2014-3120',
            'type': 'RCE',
            'description': 'ElasticSearch命令执行'
        },
        {
            'vul_id': 'CVE-2015-1427',
            'type': 'RCE',
            'description': 'ElasticSearch Groovy 沙盒绕过&&代码执行'
        },
        {
            'vul_id': 'CVE-2015-3337',
            'type': 'FileRead',
            'description': 'ElasticSearch 目录穿越'
        },
        {
            'vul_id': 'CVE-2015-5531',
            'type': 'FileRead',
            'description': 'ElasticSearch 目录穿越'
        },
    ],
    'F5 BIG-IP': [
        {
            'vul_id': 'CVE-2020-5902',
            'type': 'RCE',
            'description': 'BIG-IP远程代码执行'
        },
        {
            'vul_id': 'CVE-2022-1388',
            'type': 'unAuth',
            'description': 'BIG-IP身份认证绕过'
        }
    ],
    'Fastjson': [
        {
            'vul_id': 'CNVD-2017-02833',
            'type': 'unSerialize',
            'description': 'Fastjson <= 1.2.24 反序列化'
        },
        {
            'vul_id': 'CNVD-2019-22238',
            'type': 'unSerialize',
            'description': 'Fastjson <= 1.2.47 反序列化'
        }
    ],
    'Gitea': [
        {
            'vul_id': 'None',
            'type': 'unAuth',
            'description': 'Gitea 1.4.0 未授权访问'
        },
    ],
    'Gitlab': [
        {
            'vul_id': 'CVE-2021-22205',
            'type': 'RCE',
            'description': 'GitLab Pre-Auth 远程命令执行'
        },
        {
            'vul_id': 'CVE-2021-22214',
            'type': 'SSRF',
            'description': 'Gitlab CI Lint API未授权 SSRF'
        }
    ],
    'Grafana': [
        {
            'vul_id': 'CVE-2021-43798',
            'type': 'FileRead',
            'description': 'Grafana 8.x 插件模块路径遍历'
        },
    ],
    'Influxdb': [
        {
            'vul_id': 'None',
            'type': 'unAuth',
            'description': 'influxdb 未授权访问'
        },
    ],
    'Jenkins': [
        {
            'vul_id': 'CVE-2018-1000861',
            'type': 'RCE',
            'description': 'jenkins 远程命令执行'
        }
    ],
    'Jetty': [
        {
            'vul_id': 'CVE-2021-28164',
            'type': 'DSinfo',
            'description': 'jetty 模糊路径信息泄露'
        },
        {
            'vul_id': 'CVE-2021-28169',
            'type': 'DSinfo',
            'description': 'jetty Utility Servlets ConcatServlet 双重解码信息泄露'
        },
        {
            'vul_id': 'CVE-2021-34429',
            'type': 'DSinfo',
            'description': 'jetty 模糊路径信息泄露'
        }
    ],
    'Jupyter': [
        {
            'vul_id': 'None',
            'type': 'unAuth',
            'description': 'Jupyter 未授权访问'
        }
    ],
    'Keycloak': [
        {
            'vul_id': 'CVE-2020-10770',
            'type': 'SSRF',
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
    'Landray': [
        {
            'vul_id': 'CNVD-2021-28277',
            'type': 'FileRead/SSRF',
            'description': '蓝凌OA 任意文件读取/SSRF'
        }
    ],
    'Mini Httpd': [
        {
            'vul_id': 'CVE-2018-18778',
            'type': 'FileRead',
            'description': 'mini_httpd 任意文件读取'
        }
    ],
    'mongo-express': [
        {
            'vul_id': 'CVE-2019-10758',
            'type': 'RCE',
            'description': '未授权远程代码执行'
        }
    ],
    'Nexus Repository': [
        {
            'vul_id': 'CVE-2019-5475',
            'type': 'RCE',
            'description': '2.x yum插件 远程命令执行'
        },
        {
            'vul_id': 'CVE-2019-7238',
            'type': 'RCE',
            'description': '3.x 远程命令执行'
        },
        {
            'vul_id': 'CVE-2019-15588',
            'type': 'RCE',
            'description': '2019-5475的绕过'
        },
        {
            'vul_id': 'CVE-2020-10199',
            'type': 'RCE',
            'description': '3.x 远程命令执行'
        },
        {
            'vul_id': 'CVE-2020-10204',
            'type': 'RCE',
            'description': '3.x 远程命令执行'
        }
    ],
    'Nodejs': [
        {
            'vul_id': 'CVE-2017-14849',
            'type': 'FileRead',
            'description': 'Node.js目录穿越'
        },
        {
            'vul_id': 'CVE-2021-21315',
            'type': 'RCE',
            'description': 'Node.js命令执行'
        }
    ],
    'NodeRED': [
        {
            'vul_id': 'CVE-2021-3223',
            'type': 'FileRead',
            'description': 'Node-RED 任意文件读取'
        }
    ],
    'Ruby on Rails': [
        {
            'vul_id': 'CVE-2018-3760',
            'type': 'FileRead',
            'description': 'Ruby on Rails 路径遍历'
        },
        {
            'vul_id': 'CVE-2019-5418',
            'type': 'FileRead',
            'description': 'Ruby on Rails 任意文件读取'
        },
        {
            'vul_id': 'CVE-2020-8163',
            'type': 'RCE',
            'description': 'Ruby on Rails 命令执行'
        }
    ],
    'ShowDoc': [
        {
            'vul_id': 'CNVD-2020-26585',
            'type': 'FileUpload',
            'description': 'ShowDoc 任意文件上传'
        }
    ],
    'Spring': [
        {
            'vul_id': 'CVE-2020-5410',
            'type': 'FileRead',
            'description': 'Spring Cloud目录遍历'
        },
        {
            'vul_id': 'CVE-2021-21234',
            'type': 'FileRead',
            'description': 'Spring Boot目录遍历'
        },
        {
            'vul_id': 'CVE-2022-22947',
            'type': 'RCE',
            'description': 'Spring Cloud Gateway SpEl远程代码执行'
        },
        {
            'vul_id': 'CVE-2022-22963',
            'type': 'RCE',
            'description': 'Spring Cloud Function SpEL远程代码执行'
        },
        {
            'vul_id': 'CVE-2022-22965',
            'type': 'RCE',
            'description': 'Spring Framework远程代码执行'
        }
    ],
    'ThinkPHP': [
        {
            'vul_id': 'CVE-2018-1002015',
            'type': 'RCE',
            'description': 'ThinkPHP5.x 远程代码执行'
        },
        {
            'vul_id': 'CNVD-2018-24942',
            'type': 'RCE',
            'description': '未开启强制路由导致RCE'
        },
        {
            'vul_id': 'CNNVD-201901-445',
            'type': 'RCE',
            'description': '核心类Request远程代码执行'
        },
        {
            'vul_id': 'None',
            'type': 'RCE',
            'description': 'ThinkPHP2.x 远程代码执行'
        },
        {
            'vul_id': 'None',
            'type': 'SQLinject',
            'description': 'ThinkPHP5 ids参数SQL注入'
        }
    ],
    'Ueditor': [
        {
            'vul_id': 'None',
            'type': 'SSRF',
            'description': 'Ueditor编辑器SSRF'
        }
    ],
    'Oracle Weblogic': [
        {
            'vul_id': 'CVE-2014-4210',
            'type': 'SSRF',
            'description': 'Weblogic 服务端请求伪造'
        },
        {
            'vul_id': 'CVE-2017-10271',
            'type': 'unSerialize',
            'description': 'Weblogic XMLDecoder反序列化'
        },
        {
            'vul_id': 'CVE-2019-2725',
            'type': 'unSerialize',
            'description': 'Weblogic wls9_async反序列化'
        },
        {
            'vul_id': 'CVE-2020-14750',
            'type': 'unAuth',
            'description': 'Weblogic 权限验证绕过'
        },
        {
            'vul_id': 'CVE-2020-14882',
            'type': 'RCE',
            'description': 'Weblogic 未授权命令执行'
        }
    ],
    'Webmin': [
        {
            'vul_id': 'CVE-2019-15107',
            'type': 'RCE',
            'description': 'Webmin Pre-Auth 远程代码执行'
        },
        {
            'vul_id': 'CVE-2019-15642',
            'type': 'RCE',
            'description': 'Webmin 远程代码执行'
        }
    ],
    'Yonyou': [
        {
            'vul_id': 'CNNVD-201610-923',
            'type': 'SQLinject',
            'description': '用友GRP-U8 Proxy SQL注入'
        },
        {
            'vul_id': 'CNVD-2021-30167',
            'type': 'RCE',
            'description': '用友NC BeanShell远程命令执行'
        },
        {
            'vul_id': 'None',
            'type': 'FileRead',
            'description': '用友ERP-NC NCFindWeb目录遍历'
        },
        {
            'vul_id': 'None',
            'type': 'DSinfo',
            'description': '用友U8 OA getSessionList.jsp 敏感信息泄漏'
        },
        {
            'vul_id': 'None',
            'type': 'SQLinject',
            'description': '用友U8 OA test.jsp SQL注入'
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