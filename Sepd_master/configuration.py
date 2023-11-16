#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ast import AST
import sys, os, inspect, logging
#项目根路径
current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
PROJECT_ROOT = parent_dir.rstrip('/') + '/'

#数据存储的根目录
DATA_ROOT_PATH = "./data"
SYN_DATA_ROOT_PATH = DATA_ROOT_PATH + "/equal_patch_data/synthetic_patch"


#配置补丁存储相关参数
SAVE_PATCH_PATH = SYN_DATA_ROOT_PATH + "/sourcecode/%s/%s/" #存储补丁根目录 ./sourcecode/{year}/{cve}/
SAVE_PATCH_PATH2 = SYN_DATA_ROOT_PATH + "/sourcecode/%s/"
SAVE_PATCH_TEST_PATH = SYN_DATA_ROOT_PATH + "/sourcecode_test/%s/%s/"  #存储补丁测试根目录 ./sourcecode_test/{year}/{cve}/
SAVE_PATCH_TEST_PATH2 =  SYN_DATA_ROOT_PATH + "/sourcecode/%s/"

# 这个列表用于检查是否已经扫描过该CVE
INSPECT_PATCH_FILE_KEYWORD = "source" # 定义关键字，包含source关键字的文件夹将被检查，是否已包含CVE

ZHIDING_CVE = SYN_DATA_ROOT_PATH +  "/sourcecode/%s/"


REPO_PROJECT_PATH = PROJECT_ROOT + "data/MyProj/"


#存储source的路径
SAVE_PATCH = SYN_DATA_ROOT_PATH + "/sourcecode/"

#存储已经扫描过的cve的目录

CVE_SOURCE_PATH = SYN_DATA_ROOT_PATH +"/sourcecode/%s/"
CVE_TONGJI_PATH = SYN_DATA_ROOT_PATH +"/sourcecode/"

#时间参数
START_YEAR = 2017
END_YEAR = 2018
# 控制补丁数量
AFTER_PATCH_COUNTS = 20 # 控制natural 补丁 aftercommit的数量
AST_PATCH_COUNTS = 1 # 控制AST等价控制流的类别数量；上限为6