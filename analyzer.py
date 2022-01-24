# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"


import argparse
from utils import analyze


def analyze_dynamic_key(key):
    version = key[:3]
    analyze_handler = {
        '003': analyze.analyze_key_v3,
        '004': analyze.analyze_key_v4,
        '005': analyze.analyze_key_v5,
        '006': analyze.analyze_key_v6,
    }
    try:
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
    except Exception as e:
        print('Error: failed, error: {}'.format(repr(e)))


def main():
    arg_parser = argparse.ArgumentParser(description='Analyze Agora Token')
    arg_parser.add_argument('token', help='agora token')
    args = arg_parser.parse_args()

    analyze_dynamic_key(args.token)


if __name__ == '__main__':
    main()
