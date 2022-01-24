# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"

import argparse
from utils import check


def check_dynamic_key(key, channel, user):
    version = key[:3]
    check_handler = {
        '006': check.check_key_v6,
    }
    try:
        if version in check_handler:
            print('version: ', version)
            check_handler[version](key, channel, user)
        # else:
        #     ret = analyze.analyze_key_v2(key)
        #     if ret[0]:
        #         return
        #     ret = analyze.analyze_key_v1(key)
        #     if ret[0]:
        #         return
        #     print('Error: analyze key failed')
    except Exception as e:
        print('[Check] failed, error: {}'.format(repr(e)))


def main():
    arg_parser = argparse.ArgumentParser(description='Check Agora Token')
    arg_parser.add_argument('token', help='agora token')
    arg_parser.add_argument('-c', '--channel', type=str, required=False, help='channel name', default='')
    arg_parser.add_argument('-u', '--user', type=str, required=False, help='user id', default='')
    args = arg_parser.parse_args()

    check_dynamic_key(args.token, args.channel, args.user)


if __name__ == '__main__':
    main()
