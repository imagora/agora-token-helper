# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"

import hmac
import ctypes
from agoratoken import token
from hashlib import sha1


class AgoraTokenV1(token.AgoraToken):
    """
    | signature(hex format, 40B) | app id(32B) | ts(10B) | salt(8B) |
    """
    kVersion = '001'

    def __init__(self, app_id, app_cert, issue_ts, salt):
        super(AgoraTokenV1, self).__init__(AgoraTokenV1.kVersion, app_id, app_cert, issue_ts, salt)

    def __sign(self, channel_name):
        content = self._app_id() + '{:0>10}'.format(self.issue_ts) + "%.8x" % (int(self.salt) & 0xFFFFFFFF) + \
                  str(channel_name)
        signature = hmac.new(self.app_cert.encode('utf-8'), content.encode('utf-8'), sha1).hexdigest()
        return signature

    def token(self, channel_name):
        if not self.app_cert:
            return ''

        salt = ctypes.c_uint(self.salt).value
        signature = self.__sign(channel_name)
        ret = str(signature) + self.app_id + '{0:0>10}'.format(self.issue_ts) + "%.8x" % (int(salt) & 0xFFFFFFFF)
        return ret

    @staticmethod
    def analyze(key):
        if len(key) != 90:
            return False, None, None, None, None

        try:
            pos = 0
            signature = key[pos:40 + pos]
            pos += 40
            app_id = key[pos:32 + pos]
            pos += 32
            ts = key[pos:10 + pos]
            pos += 10
            random_int = key[pos:8 + pos]
        except:
            return False, None, None, None, None
        return True, signature, app_id, ts, random_int
