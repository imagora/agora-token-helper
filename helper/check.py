# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"

import hmac
import json
import time

from zlib import crc32
from utils import packer
from hashlib import sha256
from collections import OrderedDict

from agoratoken import token_v6


def check_key_v6(key, **kwargs):
    parsed, signature, app_id, cname_crc, uid_crc, ts, salt, privilege = token_v6.AgoraTokenV6.analyze(key)
    if not parsed:
        print('[Check] Failed to analyze token')
        return
    print('[Check] AccessToken(V6), Signature: {}, AppId: {}, CRC(ChannelName): {}, CRC(Uid): {}, Ts: {}, '
          'Salt: {}, privilege: {}'.format(signature, app_id, cname_crc, uid_crc, ts, salt,
                                           ','.join(['{}:{}'.format(x, y) for x, y in privilege.items()])))

    now_ts = int(time.time())
    if ts < now_ts:
        print('[Check] Error: token expired, now ts: {}, expired at {}'.format(now_ts, ts))

    for p, t in privilege.items():
        if t < now_ts:
            print('[Check] Error: token privilege expired, privilege: {}, now ts: {}, expired at {}'.format(p, now_ts, t))

    with open('configs/project.json') as f:
        project = json.load(f)
        config_app_id = project.get('appID', '')
        config_app_cert = project.get('appCert', '')

    if config_app_id != app_id:
        print('[Check] Error: appID not same, stop checker')
        return

    params = dict(kwargs)
    channel = params.get('channel', '')
    user = params.get('user', '')
    if not channel and not user:
        print('[Check] Warn: cname, uid and signature not checked')
        return

    if cname_crc != crc32(channel.encode('utf-8')) & 0xffffffff:
        print('[Check] Error: channel name crc32 not same')

    if uid_crc != crc32(user.encode('utf-8')) & 0xffffffff:
        print('[Check] Error: user id crc32 not same')

    val = app_id.encode('utf-8') + channel.encode('utf-8') + user.encode('utf-8') + packer.pack_uint32(salt) + \
        packer.pack_uint32(ts) + packer.pack_map_uint32(OrderedDict(sorted(iter(privilege.items()), key=lambda x: int(x[0]))))

    if signature != hmac.new(config_app_cert.encode('utf-8'), val, sha256).digest().hex():
        print('[Check] Error: signature not same')


