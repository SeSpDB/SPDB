#!/usr/bin/env python
# -*- coding: utf-8 -*-

from . import  as config

import pymysql
import os


if __name__ == '__main__':
    CVE_lists = os.listdir(config.SAVE_PATCH)
    