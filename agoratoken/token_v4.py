# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"

import hmac

from agoratoken import token
from hashlib import sha1


class AgoraTokenV4(token.AgoraToken):
    """
    | version(3B) | signature(hex format, 40B) | app id(32B) | ts(10B) | salt(8B) | expire(10B) |
    """
    kVersion = '004'

    kServicePublishSharing = 'APSS'
    kServiceRecording = 'ARS'
    kServiceMediaChannel = 'ACS'

    def __init__(self, app_id, app_cert, issue_ts, salt, expired_ts):
        super(AgoraTokenV4, self).__init__(AgoraTokenV4.kVersion, app_id, app_cert, issue_ts, salt, expired_ts)

    def __sign(self, channel_name, uid, service_type):
        content = service_type + self._app_id() + '{:0>10}'.format(self.issue_ts) + \
            "%.8x" % (int(self._salt()) & 0xFFFFFFFF) + str(channel_name) + '{:0>10}'.format(uid) + \
            '{:0>10}'.format(self.expired_ts)
        signature = hmac.new(self.app_cert.encode('utf-8'), content.encode('utf-8'), sha1).hexdigest()
        return signature

    def token(self, channel_name, uid, service_type):
        if not self.app_cert:
            return ''

        uid = AgoraTokenV4._uid(uid)
        signature = self.__sign(channel_name, uid, service_type)
        ret = self._version() + str(signature) + self.app_id + '{0:0>10}'.format(self.issue_ts) + \
            "%.8x" % (int(self._salt()) & 0xFFFFFFFF) + '{:0>10}'.format(self.expired_ts)
        return ret

    @staticmethod
    def analyze(key):
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
        except:
            return False, None, None, None, None, None
        return True, signature, app_id, ts, random_int, expired_ts