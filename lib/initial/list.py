#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import color
from lib.initial.language import language
import sys

list_lang = language()['list']
description_t = '\t\t'            # * 中英文标题的长度不一样, 中文需要添加\t才能对齐

# * ---横线长度---
Target_len_ = '-' * 58
# Target_len_ = '-' * 22
# Vul_id_len_ = '-' * 20
# Type_len_ = '-' * 14
Shell_len_ = '-' * 5
Description_len_ = '-' * 70

# * 中英文长度的处理
if ('Alibaba Druid unAuthorized' in list_lang['Alibaba Druid']):
    Description_len_ = '-' * 62
    description_t = ''

def list():
    ''' 显示漏洞列表 '''
    vul_num = 0
    shell_num = 0
    vul_list = ''
    
    vul_list += '+' + Target_len_ + '+' + Shell_len_ + '+' + Description_len_ + '+\n'
    # vul_list += '+' + Target_len_ + '+' + Vul_id_len_ + '+' + Type_len_ + '+' + Shell_len_ + '+' + Description_len_ + '+\n'

    for vul in vul_info:
        for info in vul_info[vul]:
            vul_num += 1
            if info['shell'] in ['Y', 'M']:
                shell_num += 1
            vul_list += '| {}|'.format(info['payload'].ljust(57))
            # vul_list += ' {}|'.format(info['vul_id'].ljust(19))
            # vul_list += ' {}|'.format(info['type'].ljust(13))
            vul_list += ' {}|'.format(info['shell'].center(4))
            vul_list += ' {}\t\t|'.format(info['description'].ljust(51))
            vul_list += '\n'
        # vul_list += '+' + Target_len_ + '+' + Vul_id_len_ + '+' + Type_len_ + '+' + Shell_len_ + '+' + Description_len_ + '+\n'
        vul_list += '+' + Target_len_ + '+' + Shell_len_ + '+' + Description_len_ + '+\n'

    print(color.cyan(vul_list + 'vulcat-2.0.0/2023.03.15'))    # * 2023-03-15 09:00:00
    print(color.cyan(str(vul_num - 1) + '/Poc'))               # * 有一个是标题, 所以要-1
    print(color.cyan(str(shell_num) + '/Shell'))
    # print(vul_num)
    sys.exit(0)

vul_info = {
    'Target': [
        {
            'payload': 'Payloads',
            'shell': 'Sh ',
            'description': 'Description' + description_t
        }
    ],
    '74cms': [
        {
            'payload': '74cms-v5.0.1-sqlinject',
            'shell': '-',
            'description': list_lang['74cms']['v5.0.1-sqlinject']
        },
        {
            'payload': '74cms-v6.0.4-xss',
            'shell': '-',
            'description': list_lang['74cms']['v6.0.4-xss']
        }
    ],
    'Alibaba Druid': [
        {
            'payload': 'alibaba-druid-unauth',
            'shell': '-',
            'description': list_lang['Alibaba Druid']
        }
    ],
    'Alibaba Nacos': [
        {
            'payload': 'alibaba-nacos-cve-2021-29441-unauth',
            'shell': '-',
            'description': list_lang['Alibaba Nacos']['CVE-2021-29441']
        }
    ],
    'Apache Airflow': [
        {
            'payload': 'apache-airflow-cve-2020-17526-unauth',
            'shell': '-',
            'description': list_lang['Apache Airflow']['CVE-2020-17526']
        }
    ],
    'Apache APISIX': [
        {
            'payload': 'apache-apisix-cve-2020-13945-unauth',
            'shell': '-',
            'description': list_lang['Apache APISIX']['CVE-2020-13945']
        }
    ],
    'Apache Druid': [
        {
            'payload': 'apache-druid-cve-2021-25646-rce',
            'shell': 'Y',
            'description': list_lang['Apache Druid']['CVE-2021-25646']
        },
        {
            'payload': 'apache-druid-cve-2021-36749-fileread',
            'shell': 'Y',
            'description': list_lang['Apache Druid']['CVE-2021-36749']
        },
    ],
    'Apache Flink': [
        {
            'payload': 'apache-flink-cve-2020-17519-fileread',
            'shell': 'Y',
            'description': list_lang['Apache Flink']['CVE-2020-17519']
        }
    ],
    'Apache Hadoop': [
        {
            'payload': 'apache-hadoop-unauth',
            'shell': '-',
            'description': list_lang['Apache Hadoop']
        }
    ],
    'Apache Httpd': [
        {
            'payload': 'apache-httpd-cve-2021-40438-ssrf',
            'shell': '-',
            'description': list_lang['Apache Httpd']['CVE-2021-40438']
        },
        {
            'payload': 'apache-httpd-cve-2021-41773-rce-fileread',
            'shell': 'Y',
            'description': list_lang['Apache Httpd']['CVE-2021-41773']
        },
        {
            'payload': 'apache-httpd-cve-2021-42013-rce-fileread',
            'shell': 'Y',
            'description': list_lang['Apache Httpd']['CVE-2021-42013']
        }
    ],
    'Apache SkyWalking': [
        {
            'payload': 'apache-skywalking-cve-2020-9483-sqlinject',
            'shell': '-',
            'description': list_lang['Apache SkyWalking']['CVE-2020-9483']
        }
    ],
    'Apache Solr': [
        {
            'payload': 'apache-solr-cve-2017-12629-rce',
            'shell': '-',
            'description': list_lang['Apache Solr']['CVE-2017-12629']
        },
        {
            'payload': 'apache-solr-cve-2019-17558-rce',
            'shell': 'Y',
            'description': list_lang['Apache Solr']['CVE-2019-17558']
        },
        {
            'payload': 'apache-solr-cve-2021-27905-ssrf-fileread',
            'shell': 'Y',
            'description': list_lang['Apache Solr']['CVE-2021-27905']
        },
    ],
    'Apache Tomcat': [
        {
            'payload': 'apache-tomcat-cve-2017-12615-fileupload',
            'shell': '-',
            'description': list_lang['Apache Tomcat']['CVE-2017-12615']
        }
    ],
    'Apache Unomi': [
        {
            'payload': 'apache-unomi-cve-2020-13942-rce',
            'shell': 'Y',
            'description': list_lang['Apache Unomi']['CVE-2020-13942']
        }
    ],
    'AppWeb': [
        {
            'payload': 'appweb-cve-2018-8715-unauth',
            'shell': '-',
            'description': list_lang['AppWeb']['CVE-2018-8715']
        }
    ],
    'Atlassian Confluence': [
        {
            'payload': 'atlassian-confluence-cve-2015-8399-fileread-fileinclude',
            'shell': 'Y',
            'description': list_lang['Atlassian Confluence']['CVE-2015-8399']
        },
        {
            'payload': 'atlassian-confluence-cve-2019-3396-fileread',
            'shell': 'Y',
            'description': list_lang['Atlassian Confluence']['CVE-2019-3396']
        },
        {
            'payload': 'atlassian-confluence-cve-2021-26084-rce',
            'shell': 'Y',
            'description': list_lang['Atlassian Confluence']['CVE-2021-26084']
        },
        {
            'payload': 'atlassian-confluence-cve-2022-26134-rce',
            'shell': 'Y',
            'description': list_lang['Atlassian Confluence']['CVE-2022-26134']
        }
    ],
    'Cisco': [
        {
            'payload': 'cisco-cve-2020-3580-xss',
            'shell': '-',
            'description': list_lang['Cisco']['CVE-2020-3580']
        }
    ],
    'Discuz': [
        {
            'payload': 'discuz-wooyun-2010-080723-rce',
            'shell': 'Y',
            'description': list_lang['Discuz']['wooyun-2010-080723']
        }
    ],
    'Django': [
        {
            'payload': 'django-cve-2017-12794-xss',
            'shell': '-',
            'description': list_lang['Django']['CVE-2017-12794']
        },
        {
            'payload': 'django-cve-2018-14574-redirect',
            'shell': '-',
            'description': list_lang['Django']['CVE-2018-14574']
        },
        {
            'payload': 'django-cve-2019-14234-sqlinject',
            'shell': '-',
            'description': list_lang['Django']['CVE-2019-14234']
        },
        {
            'payload': 'django-cve-2020-9402-sqlinject',
            'shell': '-',
            'description': list_lang['Django']['CVE-2020-9402']
        },
        {
            'payload': 'django-cve-2021-35042-sqlinject',
            'shell': '-',
            'description': list_lang['Django']['CVE-2021-35042']
        }
    ],
    'Drupal': [
        {
            'payload': 'drupal-cve-2014-3704-sqlinject',
            'shell': '-',
            'description': list_lang['Drupal']['CVE-2014-3704']
        },
        {
            'payload': 'drupal-cve-2017-6920-rce',
            'shell': '-',
            'description': list_lang['Drupal']['CVE-2017-6920']
        },
        {
            'payload': 'drupal-cve-2018-7600-rce',
            'shell': 'Y',
            'description': list_lang['Drupal']['CVE-2018-7600']
        },
        {
            'payload': 'drupal-cve-2018-7602-rce',
            'shell': '-',
            'description': list_lang['Drupal']['CVE-2018-7602']
        }
    ],
    'ElasticSearch': [
        {
            'payload': 'elasticsearch-cve-2014-3120-rce',
            'shell': 'Y',
            'description': list_lang['ElasticSearch']['CVE-2014-3120']
        },
        {
            'payload': 'elasticsearch-cve-2015-1427-rce',
            'shell': 'Y',
            'description': list_lang['ElasticSearch']['CVE-2015-1427']
        },
        {
            'payload': 'elasticsearch-cve-2015-3337-fileread',
            'shell': 'Y',
            'description': list_lang['ElasticSearch']['CVE-2015-3337']
        },
        {
            'payload': 'elasticsearch-cve-2015-5531-fileread',
            'shell': 'Y',
            'description': list_lang['ElasticSearch']['CVE-2015-5531']
        },
    ],
    'F5 BIG-IP': [
        {
            'payload': 'f5bigip-cve-2020-5902-rce-fileread',
            'shell': '-',
            'description': list_lang['F5 BIG-IP']['CVE-2020-5902']
        },
        {
            'payload': 'f5bigip-cve-2022-1388-unauth-rce',
            'shell': 'Y',
            'description': list_lang['F5 BIG-IP']['CVE-2022-1388']
        }
    ],
    'Fastjson': [
        {
            'payload': 'fastjson-cnvd-2017-02833-rce',
            'shell': 'Y',
            'description': list_lang['Fastjson']['CNVD-2017-02833']
        },
        {
            'payload': 'fastjson-cnvd-2019-22238-rce',
            'shell': 'Y',
            'description': list_lang['Fastjson']['CNVD-2019-22238']
        },
        {
            'payload': 'fastjson-v1.2.62-rce',
            'shell': 'Y',
            'description': list_lang['Fastjson']['rce-1-2-62']
        },
        {
            'payload': 'fastjson-v1.2.66-rce',
            'shell': 'Y',
            'description': list_lang['Fastjson']['rce-1-2-66']
        }
    ],
    'Gitea': [
        {
            'payload': 'gitea-unauth-fileread-rce',
            'shell': '-',
            'description': list_lang['Gitea']
        },
    ],
    'Gitlab': [
        {
            'payload': 'gitlab-cve-2021-22205-rce.py',
            'shell': '-',
            'description': list_lang['Gitlab']['CVE-2021-22205']
        },
        {
            'payload': 'gitlab-cve-2021-22214-ssrf',
            'shell': 'Y',
            'description': list_lang['Gitlab']['CVE-2021-22214']
        }
    ],
    'GoCD': [
        {
            'payload': 'gocd-cve-2021-43287-fileread',
            'shell': 'Y',
            'description': list_lang['GoCD']['CVE-2021-43287']
        },
    ],
    'Grafana': [
        {
            'payload': 'grafana-cve-2021-43798-fileread',
            'shell': 'Y',
            'description': list_lang['Grafana']['CVE-2021-43798']
        },
    ],
    'Influxdb': [
        {
            'payload': 'influxdb-unauth',
            'shell': '-',
            'description': list_lang['Influxdb']
        },
    ],
    'JBoss': [
        {
            'payload': 'jboss-unauth',
            'shell': '-',
            'description': list_lang['JBoss']['unAuth']
        }
    ],
    'Jenkins': [
        {
            'payload': 'jenkins-cve-2018-1000861-rce',
            'shell': 'Y',
            'description': list_lang['Jenkins']['CVE-2018-1000861']
        },
        {
            'payload': 'jenkins-unauth',
            'shell': 'Y',
            'description': list_lang['Jenkins']['unAuth']
        },
    ],
    'Jetty': [
        {
            'payload': 'jetty-cve-2021-28164-dsinfo',
            'shell': '-',
            'description': list_lang['Jetty']['CVE-2021-28164']
        },
        {
            'payload': 'jetty-cve-2021-28169-dsinfo',
            'shell': '-',
            'description': list_lang['Jetty']['CVE-2021-28169']
        },
        {
            'payload': 'jetty-cve-2021-34429-dsinfo',
            'shell': '-',
            'description': list_lang['Jetty']['CVE-2021-34429']
        }
    ],
    'Joomla': [
        {
            'payload': 'joomla-cve-2017-8917-sqlinject',
            'shell': '-',
            'description': list_lang['Joomla']['CVE-2017-8917']
        },
        {
            'payload': 'joomla-cve-2023-23752-unauth',
            'shell': '-',
            'description': list_lang['Joomla']['CVE-2023-23752']
        },
    ],
    'Jupyter': [
        {
            'payload': 'jupyter-unauth',
            'shell': '-',
            'description': list_lang['Jupyter']
        }
    ],
    'Keycloak': [
        {
            'payload': 'keycloak-cve-2020-10770-ssrf',
            'shell': '-',
            'description': list_lang['Keycloak']['CVE-2020-10770']
        }
    ],
    # 'Kindeditor': [
    #     {
    #         'payload': '',
    #         'type': 'FileRead',
    #         'method': 'GET',
    #         'description': list_lang['']['']
    #     }
    # ],
    'Landray': [
        {
            'payload': 'landray-oa-cnvd-2021-28277-ssrf-fileread',
            'shell': 'Y',
            'description': list_lang['Landray']['CNVD-2021-28277']
        }
    ],
    'Mini Httpd': [
        {
            'payload': 'minihttpd-cve-2018-18778-fileread',
            'shell': '-',
            'description': list_lang['Mini Httpd']['CVE-2018-18778']
        }
    ],
    'mongo-express': [
        {
            'payload': 'mongoexpress-cve-2019-10758-rce',
            'shell': 'Y',
            'description': list_lang['mongo-express']['CVE-2019-10758']
        }
    ],
    'Nexus Repository': [
        {
            'payload': 'nexus-cve-2019-5475-rce',
            'shell': 'Y',
            'description': list_lang['Nexus Repository']['CVE-2019-5475']
        },
        {
            'payload': 'nexus-cve-2019-7238-rce',
            'shell': 'Y',
            'description': list_lang['Nexus Repository']['CVE-2019-7238']
        },
        {
            'payload': 'nexus-cve-2019-15588-rce',
            'shell': 'Y',
            'description': list_lang['Nexus Repository']['CVE-2019-15588']
        },
        {
            'payload': 'nexus-cve-2020-10199-rce',
            'shell': 'Y',
            'description': list_lang['Nexus Repository']['CVE-2020-10199']
        },
        {
            'payload': 'nexus-cve-2020-10204-rce',
            'shell': 'Y',
            'description': list_lang['Nexus Repository']['CVE-2020-10204']
        }
    ],
    'Nodejs': [
        {
            'payload': 'nodejs-cve-2017-14849-fileread',
            'shell': 'Y',
            'description': list_lang['Nodejs']['CVE-2017-14849']
        },
        {
            'payload': 'nodejs-cve-2021-21315-rce',
            'shell': 'Y',
            'description': list_lang['Nodejs']['CVE-2021-21315']
        }
    ],
    'NodeRED': [
        {
            'payload': 'nodered-cve-2021-3223-fileread',
            'shell': 'Y',
            'description': list_lang['NodeRED']['CVE-2021-3223']
        }
    ],
    'phpMyadmin': [
        {
            'payload': 'phpmyadmin-cve-2018-12613-fileinclude-fileread',
            'shell': '-',
            'description': list_lang['phpMyadmin']['WooYun-2016-199433']
        },
        {
            'payload': 'phpmyadmin-wooyun-2016-199433-unserialize',
            'shell': 'Y',
            'description': list_lang['phpMyadmin']['CVE-2018-12613']
        },
    ],
    'PHPUnit': [
        {
            'payload': 'phpunit-cve-2017-9841-rce',
            'shell': 'Y',
            'description': list_lang['PHPUnit']['CVE-2017-9841']
        }
    ],
    'Ruby on Rails': [
        {
            'payload': 'ruby-on-rails-cve-2018-3760-fileread',
            'shell': 'Y',
            'description': list_lang['Ruby on Rails']['CVE-2018-3760']
        },
        {
            'payload': 'ruby-on-rails-cve-2019-5418-fileread',
            'shell': 'Y',
            'description': list_lang['Ruby on Rails']['CVE-2019-5418']
        },
        {
            'payload': 'ruby-on-rails-cve-2020-8163-rce',
            'shell': '-',
            'description': list_lang['Ruby on Rails']['CVE-2020-8163']
        }
    ],
    'ShowDoc': [
        {
            'payload': 'showdoc-cnvd-2020-26585-fileupload',
            'shell': '-',
            'description': list_lang['ShowDoc']['CNVD-2020-26585']
        }
    ],
    'Spring': [
        {
            'payload': 'spring-security-oauth-cve-2016-4977-rce',
            'shell': '-',
            'description': list_lang['Spring']['CVE-2016-4977']
        },
        {
            'payload': 'spring-data-rest-cve-2017-8046-rce',
            'shell': '-',
            'description': list_lang['Spring']['CVE-2017-8046']
        },
        {
            'payload': 'spring-data-commons-cve-2018-1273-rce',
            'shell': 'Y',
            'description': list_lang['Spring']['CVE-2018-1273']
        },
        {
            'payload': 'spring-cloud-config-cve-2020-5410-fileread',
            'shell': 'Y',
            'description': list_lang['Spring']['CVE-2020-5410']
        },
        {
            'payload': 'spring-boot-cve-2021-21234-fileread',
            'shell': 'Y',
            'description': list_lang['Spring']['CVE-2021-21234']
        },
        {
            'payload': 'spring-cloud-gateway-cve-2022-22947-rce',
            'shell': '-',
            'description': list_lang['Spring']['CVE-2022-22947']
        },
        {
            'payload': 'spring-cloud-function-cve-2022-22963-rce',
            'shell': 'Y',
            'description': list_lang['Spring']['CVE-2022-22963']
        },
        {
            'payload': 'spring-cve-2022-22965-rce',
            'shell': '-',
            'description': list_lang['Spring']['CVE-2022-22965']
        },
    ],
    'Supervisor': [
        {
            'payload': 'supervisor-cve-2017-11610-rce',
            'shell': '-',
            'description': list_lang['Supervisor']['CVE-2017-11610']
        }
    ],
    'ThinkPHP': [
        {
            'payload': 'thinkphp-cve-2018-1002015-rce',
            'shell': 'Y',
            'description': list_lang['ThinkPHP']['CVE-2018-1002015']
        },
        {
            'payload': 'thinkphp-cnvd-2018-24942-rce',
            'shell': 'Y',
            'description': list_lang['ThinkPHP']['CNVD-2018-24942']
        },
        {
            'payload': 'thinkphp-cnnvd-201901-445-rce',
            'shell': 'Y',
            'description': list_lang['ThinkPHP']['CNNVD-201901-445']
        },
                {
            'payload': 'thinkphp-cnvd-2022-86535-rce',
            'shell': '-',
            'description': list_lang['ThinkPHP']['CNVD-2022-86535']
        },
        {
            'payload': 'thinkphp-2.x-rce',
            'shell': '-',
            'description': list_lang['ThinkPHP']['2.x RCE']
        },
        {
            'payload': 'thinkphp-5-ids-sqlinject',
            'shell': '-',
            'description': list_lang['ThinkPHP']['5 ids sqlinject']
        }
    ],
    'Ueditor': [
        {
            'payload': 'ueditor-ssrf',
            'shell': '-',
            'description': list_lang['Ueditor']
        }
    ],
    'uWSGI-PHP': [
        {
            'payload': 'uwsgiphp-cve-2018-7490-fileread',
            'shell': 'Y',
            'description': list_lang['uWSGI-PHP']
        }
    ],
    'VMware': [
        {
            'payload': 'vmware-vcenter-2020-10-fileread',
            'shell': 'Y',
            'description': list_lang['VMware']['2020-10-fileread']
        },
        {
            'payload': 'vmware-vcenter-cve-2021-21972-fileupload-rce',
            'shell': '-',
            'description': list_lang['VMware']['CVE-2021-21972']
        }
    ],
    'Oracle Weblogic': [
        {
            'payload': 'oracle-weblogic-cve-2014-4210-ssrf',
            'shell': '-',
            'description': list_lang['Oracle Weblogic']['CVE-2014-4210']
        },
        {
            'payload': 'oracle-weblogic-cve-2017-10271-unserialize',
            'shell': '-',
            'description': list_lang['Oracle Weblogic']['CVE-2017-10271']
        },
        {
            'payload': 'oracle-weblogic-cve-2019-2725-unserialize',
            'shell': '-',
            'description': list_lang['Oracle Weblogic']['CVE-2019-2725']
        },
        {
            'payload': 'oracle-weblogic-cve-2020-14750-bypass',
            'shell': '-',
            'description': list_lang['Oracle Weblogic']['CVE-2020-14750']
        },
        {
            'payload': 'oracle-weblogic-cve-2020-14882-rce-unauth',
            'shell': 'Y',
            'description': list_lang['Oracle Weblogic']['CVE-2020-14882']
        },
        {
            'payload': 'oracle-weblogic-cve-2021-2109-rce',
            'shell': '-',
            'description': list_lang['Oracle Weblogic']['CVE-2021-2109']
        }
    ],
    'Webmin': [
        {
            'payload': 'webmin-cve-2019-15107-rce',
            'shell': 'Y',
            'description': list_lang['Webmin']['CVE-2019-15107']
        },
        {
            'payload': 'webmin-cve-2019-15642-rce',
            'shell': 'Y',
            'description': list_lang['Webmin']['CVE-2019-15642']
        }
    ],
    'Yonyou': [
        {
            'payload': 'yonyou-grp-u8-cnnvd-201610-923-sqlinject',
            'shell': '-',
            'description': list_lang['Yonyou']['CNNVD-201610-923']
        },
        {
            'payload': 'yonyou-nc-cnvd-2021-30167-rce',
            'shell': 'Y',
            'description': list_lang['Yonyou']['CNVD-2021-30167']
        },
        {
            'payload': 'yonyou-erp-nc-ncfindweb-fileread',
            'shell': '-',
            'description': list_lang['Yonyou']['NCFindWeb']
        },
        {
            'payload': 'yonyou-u8-oa-getsession-dsinfo',
            'shell': '-',
            'description': list_lang['Yonyou']['getSessionList.jsp']
        },
        {
            'payload': 'yonyou-u8-oa-test.jsp-sqlinject',
            'shell': '-',
            'description': list_lang['Yonyou']['test.jsp']
        }
    ],
    'Zabbix': [
        {
            'payload': 'zabbix-cve-2016-10134-sqlinject',
            'shell': '-',
            'description': list_lang['Zabbix']['CVE-2016-10134']
        }
    ],
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