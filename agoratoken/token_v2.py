# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"

import hmac

from agoratoken import token
from hashlib import sha1


class AgoraTokenV2(token.AgoraToken):
    """
    | signature(hex format, 40B) | app id(32B) | ts(10B) | salt(8B) | uid(10B) | expire(10B) |
    """
    kVersion = '002'

    def __init__(self, app_id, app_cert, issue_ts, salt, expired_ts):
        super(AgoraTokenV2, self).__init__(AgoraTokenV2.kVersion, app_id, app_cert, issue_ts, salt, expired_ts)

    def __sign(self, channel_name, uid):
        content = self._app_id() + '{:0>10}'.format(self.issue_ts) + "%.8x" % (int(self.salt) & 0xFFFFFFFF) + \
            str(channel_name) + '{:0>10}'.format(uid) + '{:0>10}'.format(self.expired_ts)
        signature = hmac.new(self.app_cert.encode('utf-8'), content.encode('utf-8'), sha1).hexdigest()
        return signature

    def token(self, channel_name, uid):
        if not self.app_cert:
            return ''

        uid = AgoraTokenV2._uid(uid)
        signature = self.__sign(channel_name, uid)
        ret = str(signature) + self.app_id + '{0:0>10}'.format(self.issue_ts) + \
            "%.8x" % (int(self.salt) & 0xFFFFFFFF) + '{:0>10}'.format(uid) + '{:0>10}'.format(self.expired_ts)
        return ret

    @staticmethod
    def analyze(key):
        if len(key) != 110:
            return False, None, None, None, None, None, None

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
        except:
            return False, None, None, None, None, None, None
        return True, signature, app_id, ts, random_int, uid, expired_ts

