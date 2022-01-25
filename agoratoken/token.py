# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"


import time
import ctypes
import secrets


class AgoraToken(object):
    def __init__(self, version, app_id, app_cert, issue_ts, salt, expired_ts=0):
        self.version = version
        self.app_id = app_id
        self.app_cert = app_cert
        self.issue_ts = issue_ts if issue_ts != 0 else int(time.time())
        self.salt = salt if salt != 0 else secrets.SystemRandom().randint(1, 99999999)
        self.expired_ts = expired_ts

    def _version(self):
        return self.version

    def _app_id(self):
        return '\x00' * (32 - len(self.app_id)) + self.app_id

    def _salt(self):
        return ctypes.c_uint(self.salt).value

    @staticmethod
    def _uid(uid):
        try:
            uid = int(uid)
        except:
            return 0
        return ctypes.c_uint(uid).value

