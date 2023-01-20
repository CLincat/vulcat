#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import yaml

def load_yaml():
    f = open('config.yaml', 'r', encoding='utf-8')
    config_yaml = yaml.load(f, yaml.FullLoader)
    f.close

    return config_yaml