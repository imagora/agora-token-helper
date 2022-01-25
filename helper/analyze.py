# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"


from agoratoken import token_v1
from agoratoken import token_v2
from agoratoken import token_v3
from agoratoken import token_v4
from agoratoken import token_v5
from agoratoken import token_v6


def analyze_key_v1(key):
    ok, signature, app_id, ts, random_int = token_v1.AgoraTokenV1.analyze(key)
    if not ok:
        return False

    print('[Analyze] V1, Signature: {}, AppId: {}, Ts: {}, Salt: {}'.format(signature, app_id, ts, random_int))
    return True


def analyze_key_v2(key):
    ok, signature, app_id, ts, random_int, uid, expired_ts = token_v2.AgoraTokenV2.analyze(key)
    if not ok:
        return False

    print('[Analyze] V2, Signature: {}, AppId: {}, Ts: {}, Salt: {}, Uid: {}, Expire: {}'.format(
        signature, app_id, ts, random_int, uid, expired_ts))
    return True


def analyze_key_v3(key):
    ok, signature, app_id, ts, random_int, uid, expired_ts = token_v3.AgoraTokenV3.analyze(key)
    if not ok:
        return False
    print('[Analyze] V3, Signature: {}, AppId: {}, Ts: {}, Salt: {}, Uid: {}, Expire: {}'.format(
        signature, app_id, ts, random_int, uid, expired_ts))
    return True


def analyze_key_v4(key):
    ok, signature, app_id, ts, random_int, expired_ts = token_v4.AgoraTokenV4.analyze(key)
    if not ok:
        return False
    print('[Analyze] V4, Signature: {}, AppId: {}, Ts: {}, Salt: {}, Expire: {}'.format(
        signature, app_id, ts, random_int, expired_ts))
    return True


def analyze_key_v5(key):
    ok, signature, app_id, service_type, ts, salt, expired_ts, privilege = token_v5.AgoraTokenV5.analyze(key)
    if not ok:
        return False

    print('[Analyze] V5, Signature: {}, AppId: {}, ServiceType: {}, Ts: {}, Salt: {}, Expire: {}, privilege: {}'.format(
        signature, app_id, service_type, ts, salt, expired_ts,
        ','.join(['{}:{}'.format(x, y) for x, y in privilege.items()])))
    return True


def analyze_key_v6(key):
    ok, signature, app_id, cname_crc, uid_crc, ts, salt, privilege = token_v6.AgoraTokenV6.analyze(key)
    if not ok:
        return False

    print('[Analyze] AccessToken(V6), Signature: {}, AppId: {}, CRC(ChannelName): {}, CRC(Uid): {}, Ts: {}, '
          'Salt: {}, privilege: {}'.format(signature, app_id, cname_crc, uid_crc, ts, salt,
                                           ','.join(['{}:{}'.format(x, y) for x, y in privilege.items()])))
    return True
