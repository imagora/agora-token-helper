# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"


import sys
from utils import analyze


def analyze_dynamic_key(key):
    version = key[:3]
    analyze_handler = {
        '003': analyze.analyze_key_v3,
        '004': analyze.analyze_key_v4,
        '005': analyze.analyze_key_v5,
        '006': analyze.analyze_key_v6,
    }
    if version in analyze_handler:
        print('version: ', version)
        analyze_handler[version](key)
    else:
        ret = analyze.analyze_key_v2(key)
        if ret[0]:
            return
        ret = analyze.analyze_key_v1(key)
        if ret[0]:
            return
        print('Error: analyze key failed')


def main():
    if len(sys.argv) < 2:
        print('run as: python3 analyzer.py dynamic_key_string')
        exit(1)

    analyze_dynamic_key(sys.argv[1])


if __name__ == '__main__':
    main()
