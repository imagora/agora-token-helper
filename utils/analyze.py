# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"


import base64
from utils import packer


def analyze_key_v1(key):
    """
    | signature(hex format, 40B) | app id(32B) | ts(10B) | salt(8B) |
    """
    if len(key) != 90:
        return False, None

    try:
        pos = 0
        signature = key[pos:40 + pos]
        pos += 40
        app_id = key[pos:32 + pos]
        pos += 32
        ts = key[pos:10 + pos]
        pos += 10
        random_int = key[pos:8 + pos]
        print('[V1] Signature: {}, AppId: {}, Ts: {}, Salt: {}'.format(signature, app_id, ts, random_int))
    except:
        return False, None
    return True, signature, app_id, ts, random_int


def analyze_key_v2(key):
    """
    | signature(hex format, 40B) | app id(32B) | ts(10B) | salt(8B) | uid(10B) | expire(10B) |
    """
    if len(key) != 110:
        return False, None

    try:
        pos = 0
        signature = key[pos:40 + pos]
        pos += 40
        app_id = key[pos:32 + pos]
        pos += 32
        ts = key[pos:10 + pos]
        pos += 10
        random_int = key[pos:8 + pos]
        pos += 8
        uid = key[pos:pos + 10]
        pos += 10
        expired_ts = key[pos:pos + 10]
        print('[V2] Signature: {}, AppId: {}, Ts: {}, Salt: {}, Uid: {}, Expire: {}'.format(
            signature, app_id, ts, random_int, uid, expired_ts))
    except:
        return False, None
    return True, signature, app_id, ts, random_int, uid, expired_ts


def analyze_key_v3(key):
    """
    | version(3B) | signature(hex format, 40B) | app id(32B) | ts(10B) | salt(8B) | uid(10B) | expire(10B) |
    """
    try:
        pos = 3
        signature = key[pos:40 + pos]
        pos += 40
        app_id = key[pos:32 + pos]
        pos += 32
        ts = key[pos:10 + pos]
        pos += 10
        random_int = key[pos:8 + pos]
        pos += 8
        uid = key[pos:pos + 10]
        pos += 10
        expired_ts = key[pos:pos + 10]
        print('[V3] Signature: {}, AppId: {}, Ts: {}, Salt: {}, Uid: {}, Expire: {}'.format(
            signature, app_id, ts, random_int, uid, expired_ts))
    except Exception as e:
        print('DynamicKey3 parse failed: ' + repr(e))
        return False, None
    return True, signature, app_id, ts, random_int, uid, expired_ts


def analyze_key_v4(key):
    """
    | version(3B) | signature(hex format, 40B) | app id(32B) | ts(10B) | salt(8B) | expire(10B) |
    """
    try:
        pos = 3
        signature = key[pos:40 + pos]
        pos += 40
        app_id = key[pos:32 + pos]
        pos += 32
        ts = key[pos:10 + pos]
        pos += 10
        random_int = key[pos:8 + pos]
        pos += 8
        expired_ts = key[pos:pos + 10]
        print('[V4] Signature: {}, AppId: {}, Ts: {}, Salt: {}, Expire: {}'.format(
            signature, app_id, ts, random_int, expired_ts))
    except Exception as e:
        print('DynamicKey4 parse failed: ' + repr(e))
        return False, None
    return True, signature, app_id, ts, random_int, expired_ts


def analyze_key_v5(key):
    """
    | version(3B) | Base64(
        | service type(2B) | signature(str) | app id(str) | ts(4B) | salt(4B) | expire(4B) | privilege(map) |
    ) |
    """
    try:
        pos = 3
        buffer = base64.b64decode(key[pos:])

        service_type, buffer = packer.unpack_uint16(buffer)
        signature, buffer = packer.unpack_string(buffer)

        app_id, buffer = packer.unpack_string(buffer)
        app_id = app_id.hex()

        ts, buffer = packer.unpack_uint32(buffer)
        salt, buffer = packer.unpack_uint32(buffer)
        expired_ts, buffer = packer.unpack_uint32(buffer)
        privilege, buffer = packer.unpack_map_string(buffer)

        print('[V5] Signature: {}, AppId: {}, ServiceType: {}, Ts: {}, Salt: {}, Expire: {}, privilege: {}'.format(
            signature, app_id, service_type, ts, salt, expired_ts,
            ','.join(['{}:{}'.format(x, y) for x, y in privilege.items()])))
    except Exception as e:
        print('DynamicKey5 parse failed: ' + repr(e))
        return False, None
    return True, signature, app_id, service_type, ts, salt, expired_ts, privilege


def analyze_key_v6(key):
    """
    | version(3B) | app id(32B) | Base64(
        | signature(str) | CRC(channel name)(4B) | CRC(Uid)(4B) | salt(4B) | ts(4B) | privilege(map) |
    ) |
    """
    try:
        pos = 3
        app_id = key[pos:32 + pos]
        pos += 32
        buffer = base64.b64decode(key[pos:])

        signature, buffer = packer.unpack_string(buffer)
        signature = signature.hex()

        cname_crc, buffer = packer.unpack_uint32(buffer)
        uid_crc, buffer = packer.unpack_uint32(buffer)

        buffer, _ = packer.unpack_string(buffer)

        salt, buffer = packer.unpack_uint32(buffer)
        ts, buffer = packer.unpack_uint32(buffer)
        privilege, buffer = packer.unpack_map_uint32(buffer)

        print('[AccessToken] Signature: {}, AppId: {}, CRC(ChannelName): {}, CRC(Uid): {}, Ts: {}, '
              'Salt: {}, privilege: {}'.format(signature, app_id, cname_crc, uid_crc, ts, salt,
                                               ','.join(['{}:{}'.format(x, y) for x, y in privilege.items()])))
    except Exception as e:
        print('AccessToken parse failed: ' + repr(e))
        return False, None
    return True, signature, app_id, cname_crc, uid_crc, ts, salt, privilege
