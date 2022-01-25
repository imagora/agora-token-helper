# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"

import hmac
import base64

from agoratoken import token
from utils import packer
from hashlib import sha1


class AgoraTokenV5(token.AgoraToken):
    """
    | version(3B) | Base64(
        | service type(2B) | signature(str) | app id(str) | ts(4B) | salt(4B) | expire(4B) | privilege(map) |
    ) |

    extra_info = {}
    extra_info[kExtraInfoAllowUploadInChannel] = kPermisionAudioVideoUpload
    """
    kVersion = '005'

    kServiceMediaChannel = 1
    kServiceRecording = 2
    kServicePublishSharing = 3
    kServiceInChannelPermission = 4

    kExtraInfoAllowUploadInChannel = 1

    kPermisionNoUpload = b'0'
    kPermisionAudioVideoUpload = b'3'

    def __init__(self, app_id, app_cert, issue_ts, salt, expired_ts):
        super(AgoraTokenV5, self).__init__(AgoraTokenV5.kVersion, app_id, app_cert, issue_ts, salt, expired_ts)

    def __sign(self, channel_name, uid, service_type, extra_info):
        content = packer.pack_uint16(service_type) + packer.pack_string(bytes.fromhex(self.app_id)) + packer.pack_uint32(self.issue_ts) + \
            packer.pack_uint32(self._salt()) + packer.pack_string(channel_name) + packer.pack_uint32(uid) + packer.pack_uint32(self.expired_ts) + \
            packer.pack_map_string(extra_info)
        signature = hmac.new(bytes.fromhex(self.app_cert), content, sha1).hexdigest()
        return signature.upper()

    def token(self, channel_name, uid, service_type, extra_info):
        if not self.app_cert:
            return ''

        uid = AgoraTokenV5._uid(uid)
        signature = self.__sign(channel_name, uid, service_type, extra_info)
        content = packer.pack_uint16(service_type) + packer.pack_string(signature) + packer.pack_string(bytes.fromhex(self.app_id)) + \
            packer.pack_uint32(self.issue_ts) + packer.pack_uint32(self._salt()) + packer.pack_uint32(self.expired_ts) + \
            packer.pack_map_string(extra_info)
        return self._version() + base64.b64encode(content).decode('utf-8')

    @staticmethod
    def analyze(key):
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
        except:
            return False, None, None, None, None, None, None, None
        return True, signature, app_id, service_type, ts, salt, expired_ts, privilege
