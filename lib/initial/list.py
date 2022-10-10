#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import color
from lib.initial.language import language
import sys

list_lang = language()['list']
description_t = '\t'            # * 中英文标题的长度不一样, 中文需要添加一个\t才能对齐

# * ---横线长度---
Target_len_ = '-' * 22
Vul_id_len_ = '-' * 20
Type_len_ = '-' * 14
Description_len_ = '-' * 68

# * 中英文长度的处理
if ('Alibaba Druid unAuthorized' in list_lang['Alibaba Druid']):
    Description_len_ = '-' * 60
    description_t = ''

def list():
    ''' 显示漏洞列表 '''
    vul_num = 0
    vul_list = ''
    
    vul_list += '+' + Target_len_ + '+' + Vul_id_len_ + '+' + Type_len_ + '+' + Description_len_ + '+\n'

    for vul in vul_info:
        for info in vul_info[vul]:
            vul_num += 1
            vul_list += '| {}|'.format(vul.ljust(21))
            vul_list += ' {}|'.format(info['vul_id'].ljust(19))
            vul_list += ' {}|'.format(info['type'].ljust(13))
            vul_list += ' {}\t|'.format(info['description'].ljust(57))
            vul_list += '\n'
        vul_list += '+' + Target_len_ + '+' + Vul_id_len_ + '+' + Type_len_ + '+' + Description_len_ + '+\n'

    print(color.cyan(vul_list + str(vul_num - 1) + '/vulcat-1.1.4/2022.10'))
    # print(vul_num)
    sys.exit(0)

vul_info = {
    'Target': [
        {
            'vul_id': 'Vul_id',
            'type': 'Type',
            'description': 'Description' + description_t
        }
    ],
    'Alibaba Druid': [
        {
            'vul_id': 'None',
            'type': 'unAuth',
            'description': list_lang['Alibaba Druid']
        }
    ],
    'Alibaba Nacos': [
        {
            'vul_id': 'CVE-2021-29441',
            'type': 'unAuth',
            'description': list_lang['Alibaba Nacos']['CVE-2021-29441']
        }
    ],
    'Apache Airflow': [
        {
            'vul_id': 'CVE-2020-17526',
            'type': 'unAuth',
            'description': list_lang['Apache Airflow']['CVE-2020-17526']
        }
    ],
    'Apache APISIX': [
        {
            'vul_id': 'CVE-2020-13945',
            'type': 'unAuth',
            'description': list_lang['Apache APISIX']['CVE-2020-13945']
        }
    ],
    'Apache Flink': [
        {
            'vul_id': 'CVE-2020-17519',
            'type': 'FileRead',
            'description': list_lang['Apache Flink']['CVE-2020-17519']
        }
    ],
    'Apache Hadoop': [
        {
            'vul_id': 'None',
            'type': 'unAuth',
            'description': list_lang['Apache Hadoop']
        }
    ],
    'Apache Httpd': [
        {
            'vul_id': 'CVE-2021-40438',
            'type': 'SSRF',
            'description': list_lang['Apache Httpd']['CVE-2021-40438']
        },
        {
            'vul_id': 'CVE-2021-41773',
            'type': 'FileRead/RCE',
            'description': list_lang['Apache Httpd']['CVE-2021-41773']
        },
        {
            'vul_id': 'CVE-2021-42013',
            'type': 'FileRead/RCE',
            'description': list_lang['Apache Httpd']['CVE-2021-42013']
        }
    ],
    'Apache SkyWalking': [
        {
            'vul_id': 'CVE-2020-9483',
            'type': 'SQLinject',
            'description': list_lang['Apache SkyWalking']['CVE-2020-9483']
        }
    ],
    'Apache Solr': [
        {
            'vul_id': 'CVE-2017-12629',
            'type': 'RCE',
            'description': list_lang['Apache Solr']['CVE-2017-12629']
        },
        {
            'vul_id': 'CVE-2019-17558',
            'type': 'RCE',
            'description': list_lang['Apache Solr']['CVE-2019-17558']
        },
        {
            'vul_id': 'CVE-2021-27905',
            'type': 'SSRF',
            'description': list_lang['Apache Solr']['CVE-2021-27905']
        },
    ],
    'Apache Struts2': [
        {
            'vul_id': 'S2-001',
            'type': 'RCE',
            'description': list_lang['Apache Struts2']['S2-001']
        },
        {
            'vul_id': 'S2-005',
            'type': 'RCE',
            'description': list_lang['Apache Struts2']['S2-005']
        },
        {
            'vul_id': 'S2-007',
            'type': 'RCE',
            'description': list_lang['Apache Struts2']['S2-007']
        },
        {
            'vul_id': 'S2-008',
            'type': 'RCE',
            'description': list_lang['Apache Struts2']['S2-008']
        },
        {
            'vul_id': 'S2-009',
            'type': 'RCE',
            'description': list_lang['Apache Struts2']['S2-009']
        },
        {
            'vul_id': 'S2-012',
            'type': 'RCE',
            'description': list_lang['Apache Struts2']['S2-012']
        }
    ],
    'Apache Tomcat': [
        {
            'vul_id': 'CVE-2017-12615',
            'type': 'FileUpload',
            'description': list_lang['Apache Tomcat']['CVE-2017-12615']
        }
    ],
    'AppWeb': [
        {
            'vul_id': 'CVE-2018-8715',
            'type': 'unAuth',
            'description': list_lang['AppWeb']['CVE-2018-8715']
        }
    ],
    'Atlassian Confluence': [
        {
            'vul_id': 'CVE-2015-8399',
            'type': 'FileRead',
            'description': list_lang['Atlassian Confluence']['CVE-2015-8399']
        },
        {
            'vul_id': 'CVE-2019-3396',
            'type': 'RCE/FileRead',
            'description': list_lang['Atlassian Confluence']['CVE-2019-3396']
        },
        {
            'vul_id': 'CVE-2021-26084',
            'type': 'RCE',
            'description': list_lang['Atlassian Confluence']['CVE-2021-26084']
        },
        {
            'vul_id': 'CVE-2022-26134',
            'type': 'RCE',
            'description': list_lang['Atlassian Confluence']['CVE-2022-26134']
        }
    ],
    'Cisco': [
        {
            'vul_id': 'CVE-2020-3580',
            'type': 'XSS',
            'description': list_lang['Cisco']['CVE-2020-3580']
        }
    ],
    'Discuz': [
        {
            'vul_id': 'wooyun-2010-080723',
            'type': 'RCE',
            'description': list_lang['Discuz']['wooyun-2010-080723']
        }
    ],
    'Django': [
        {
            'vul_id': 'CVE-2017-12794',
            'type': 'XSS',
            'description': list_lang['Django']['CVE-2017-12794']
        },
        {
            'vul_id': 'CVE-2018-14574',
            'type': 'Redirect',
            'description': list_lang['Django']['CVE-2018-14574']
        },
        {
            'vul_id': 'CVE-2019-14234',
            'type': 'SQLinject',
            'description': list_lang['Django']['CVE-2019-14234']
        },
        {
            'vul_id': 'CVE-2020-9402',
            'type': 'SQLinject',
            'description': list_lang['Django']['CVE-2020-9402']
        },
        {
            'vul_id': 'CVE-2021-35042',
            'type': 'SQLinject',
            'description': list_lang['Django']['CVE-2021-35042']
        }
    ],
    'Drupal': [
        {
            'vul_id': 'CVE-2014-3704',
            'type': 'SQLinject',
            'description': list_lang['Drupal']['CVE-2014-3704']
        },
        {
            'vul_id': 'CVE-2017-6920',
            'type': 'RCE',
            'description': list_lang['Drupal']['CVE-2017-6920']
        },
        {
            'vul_id': 'CVE-2018-7600',
            'type': 'RCE',
            'description': list_lang['Drupal']['CVE-2018-7600']
        },
        {
            'vul_id': 'CVE-2018-7602',
            'type': 'RCE',
            'description': list_lang['Drupal']['CVE-2018-7602']
        }
    ],
    'ElasticSearch': [
        {
            'vul_id': 'CVE-2014-3120',
            'type': 'RCE',
            'description': list_lang['ElasticSearch']['CVE-2014-3120']
        },
        {
            'vul_id': 'CVE-2015-1427',
            'type': 'RCE',
            'description': list_lang['ElasticSearch']['CVE-2015-1427']
        },
        {
            'vul_id': 'CVE-2015-3337',
            'type': 'FileRead',
            'description': list_lang['ElasticSearch']['CVE-2015-3337']
        },
        {
            'vul_id': 'CVE-2015-5531',
            'type': 'FileRead',
            'description': list_lang['ElasticSearch']['CVE-2015-5531']
        },
    ],
    'F5 BIG-IP': [
        {
            'vul_id': 'CVE-2020-5902',
            'type': 'RCE',
            'description': list_lang['F5 BIG-IP']['CVE-2020-5902']
        },
        {
            'vul_id': 'CVE-2022-1388',
            'type': 'unAuth',
            'description': list_lang['F5 BIG-IP']['CVE-2020-5902']
        }
    ],
    'Fastjson': [
        {
            'vul_id': 'CNVD-2017-02833',
            'type': 'unSerialize',
            'description': list_lang['Fastjson']['CNVD-2017-02833']
        },
        {
            'vul_id': 'CNVD-2019-22238',
            'type': 'unSerialize',
            'description': list_lang['Fastjson']['CNVD-2019-22238']
        }
    ],
    'Gitea': [
        {
            'vul_id': 'None',
            'type': 'unAuth',
            'description': list_lang['Gitea']
        },
    ],
    'Gitlab': [
        {
            'vul_id': 'CVE-2021-22205',
            'type': 'RCE',
            'description': list_lang['Gitlab']['CVE-2021-22205']
        },
        {
            'vul_id': 'CVE-2021-22214',
            'type': 'SSRF',
            'description': list_lang['Gitlab']['CVE-2021-22214']
        }
    ],
    'Grafana': [
        {
            'vul_id': 'CVE-2021-43798',
            'type': 'FileRead',
            'description': list_lang['Grafana']['CVE-2021-43798']
        },
    ],
    'Influxdb': [
        {
            'vul_id': 'None',
            'type': 'unAuth',
            'description': list_lang['Influxdb']
        },
    ],
    'Jenkins': [
        {
            'vul_id': 'CVE-2018-1000861',
            'type': 'RCE',
            'description': list_lang['Jenkins']['CVE-2018-1000861']
        }
    ],
    'Jetty': [
        {
            'vul_id': 'CVE-2021-28164',
            'type': 'DSinfo',
            'description': list_lang['Jetty']['CVE-2021-28164']
        },
        {
            'vul_id': 'CVE-2021-28169',
            'type': 'DSinfo',
            'description': list_lang['Jetty']['CVE-2021-28169']
        },
        {
            'vul_id': 'CVE-2021-34429',
            'type': 'DSinfo',
            'description': list_lang['Jetty']['CVE-2021-34429']
        }
    ],
    'Jupyter': [
        {
            'vul_id': 'None',
            'type': 'unAuth',
            'description': list_lang['Jupyter']
        }
    ],
    'Keycloak': [
        {
            'vul_id': 'CVE-2020-10770',
            'type': 'SSRF',
            'description': list_lang['Keycloak']['CVE-2020-10770']
        }
    ],
    # 'Kindeditor': [
    #     {
    #         'vul_id': 'CVE-2018-18950',
    #         'type': 'FileRead',
    #         'method': 'GET',
    #         'description': list_lang['']['']
    #     }
    # ],
    'Landray': [
        {
            'vul_id': 'CNVD-2021-28277',
            'type': 'FileRead/SSRF',
            'description': list_lang['Landray']['CNVD-2021-28277']
        }
    ],
    'Mini Httpd': [
        {
            'vul_id': 'CVE-2018-18778',
            'type': 'FileRead',
            'description': list_lang['Mini Httpd']['CVE-2018-18778']
        }
    ],
    'mongo-express': [
        {
            'vul_id': 'CVE-2019-10758',
            'type': 'RCE',
            'description': list_lang['mongo-express']['CVE-2019-10758']
        }
    ],
    'Nexus Repository': [
        {
            'vul_id': 'CVE-2019-5475',
            'type': 'RCE',
            'description': list_lang['Nexus Repository']['CVE-2019-5475']
        },
        {
            'vul_id': 'CVE-2019-7238',
            'type': 'RCE',
            'description': list_lang['Nexus Repository']['CVE-2019-7238']
        },
        {
            'vul_id': 'CVE-2019-15588',
            'type': 'RCE',
            'description': list_lang['Nexus Repository']['CVE-2019-15588']
        },
        {
            'vul_id': 'CVE-2020-10199',
            'type': 'RCE',
            'description': list_lang['Nexus Repository']['CVE-2020-10199']
        },
        {
            'vul_id': 'CVE-2020-10204',
            'type': 'RCE',
            'description': list_lang['Nexus Repository']['CVE-2020-10204']
        }
    ],
    'Nodejs': [
        {
            'vul_id': 'CVE-2017-14849',
            'type': 'FileRead',
            'description': list_lang['Nodejs']['CVE-2017-14849']
        },
        {
            'vul_id': 'CVE-2021-21315',
            'type': 'RCE',
            'description': list_lang['Nodejs']['CVE-2021-21315']
        }
    ],
    'NodeRED': [
        {
            'vul_id': 'CVE-2021-3223',
            'type': 'FileRead',
            'description': list_lang['NodeRED']['CVE-2021-3223']
        }
    ],
    'phpMyadmin': [
        {
            'vul_id': 'WooYun-2016-199433',
            'type': 'unSerialize',
            'description': list_lang['phpMyadmin']['WooYun-2016-199433']
        },
        {
            'vul_id': 'CVE-2018-12613',
            'type': 'FileInclude',
            'description': list_lang['phpMyadmin']['CVE-2018-12613']
        },
    ],
    'PHPUnit': [
        {
            'vul_id': 'CVE-2017-9841',
            'type': 'RCE',
            'description': list_lang['PHPUnit']['CVE-2017-9841']
        }
    ],
    'Ruby on Rails': [
        {
            'vul_id': 'CVE-2018-3760',
            'type': 'FileRead',
            'description': list_lang['Ruby on Rails']['CVE-2018-3760']
        },
        {
            'vul_id': 'CVE-2019-5418',
            'type': 'FileRead',
            'description': list_lang['Ruby on Rails']['CVE-2019-5418']
        },
        {
            'vul_id': 'CVE-2020-8163',
            'type': 'RCE',
            'description': list_lang['Ruby on Rails']['CVE-2020-8163']
        }
    ],
    'ShowDoc': [
        {
            'vul_id': 'CNVD-2020-26585',
            'type': 'FileUpload',
            'description': list_lang['ShowDoc']['CNVD-2020-26585']
        }
    ],
    'Spring': [
        {
            'vul_id': 'CVE-2016-4977',
            'type': 'RCE',
            'description': list_lang['Spring']['CVE-2016-4977']
        },
        {
            'vul_id': 'CVE-2017-8046',
            'type': 'RCE',
            'description': list_lang['Spring']['CVE-2017-8046']
        },
        {
            'vul_id': 'CVE-2018-1273',
            'type': 'RCE',
            'description': list_lang['Spring']['CVE-2018-1273']
        },
        {
            'vul_id': 'CVE-2020-5410',
            'type': 'FileRead',
            'description': list_lang['Spring']['CVE-2020-5410']
        },
        {
            'vul_id': 'CVE-2021-21234',
            'type': 'FileRead',
            'description': list_lang['Spring']['CVE-2021-21234']
        },
        {
            'vul_id': 'CVE-2022-22947',
            'type': 'RCE',
            'description': list_lang['Spring']['CVE-2022-22947']
        },
        {
            'vul_id': 'CVE-2022-22963',
            'type': 'RCE',
            'description': list_lang['Spring']['CVE-2022-22963']
        },
        {
            'vul_id': 'CVE-2022-22965',
            'type': 'RCE',
            'description': list_lang['Spring']['CVE-2022-22965']
        },
    ],
    'ThinkPHP': [
        {
            'vul_id': 'CVE-2018-1002015',
            'type': 'RCE',
            'description': list_lang['ThinkPHP']['CVE-2018-1002015']
        },
        {
            'vul_id': 'CNVD-2018-24942',
            'type': 'RCE',
            'description': list_lang['ThinkPHP']['CNVD-2018-24942']
        },
        {
            'vul_id': 'CNNVD-201901-445',
            'type': 'RCE',
            'description': list_lang['ThinkPHP']['CNNVD-201901-445']
        },
        {
            'vul_id': 'None',
            'type': 'RCE',
            'description': list_lang['ThinkPHP']['2.x RCE']
        },
        {
            'vul_id': 'None',
            'type': 'SQLinject',
            'description': list_lang['ThinkPHP']['5 ids sqlinject']
        }
    ],
    'Ueditor': [
        {
            'vul_id': 'None',
            'type': 'SSRF',
            'description': list_lang['Ueditor']
        }
    ],
    'Oracle Weblogic': [
        {
            'vul_id': 'CVE-2014-4210',
            'type': 'SSRF',
            'description': list_lang['Oracle Weblogic']['CVE-2014-4210']
        },
        {
            'vul_id': 'CVE-2017-10271',
            'type': 'unSerialize',
            'description': list_lang['Oracle Weblogic']['CVE-2017-10271']
        },
        {
            'vul_id': 'CVE-2019-2725',
            'type': 'unSerialize',
            'description': list_lang['Oracle Weblogic']['CVE-2019-2725']
        },
        {
            'vul_id': 'CVE-2020-14750',
            'type': 'unAuth',
            'description': list_lang['Oracle Weblogic']['CVE-2020-14750']
        },
        {
            'vul_id': 'CVE-2020-14882',
            'type': 'RCE',
            'description': list_lang['Oracle Weblogic']['CVE-2020-14882']
        }
    ],
    'Webmin': [
        {
            'vul_id': 'CVE-2019-15107',
            'type': 'RCE',
            'description': list_lang['Webmin']['CVE-2019-15107']
        },
        {
            'vul_id': 'CVE-2019-15642',
            'type': 'RCE',
            'description': list_lang['Webmin']['CVE-2019-15642']
        }
    ],
    'Yonyou': [
        {
            'vul_id': 'CNNVD-201610-923',
            'type': 'SQLinject',
            'description': list_lang['Yonyou']['CNNVD-201610-923']
        },
        {
            'vul_id': 'CNVD-2021-30167',
            'type': 'RCE',
            'description': list_lang['Yonyou']['CNVD-2021-30167']
        },
        {
            'vul_id': 'None',
            'type': 'FileRead',
            'description': list_lang['Yonyou']['NCFindWeb']
        },
        {
            'vul_id': 'None',
            'type': 'DSinfo',
            'description': list_lang['Yonyou']['getSessionList.jsp']
        },
        {
            'vul_id': 'None',
            'type': 'SQLinject',
            'description': list_lang['Yonyou']['test.jsp']
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