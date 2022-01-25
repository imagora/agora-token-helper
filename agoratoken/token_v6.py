# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"

import hmac
import time
import base64

from zlib import crc32
from agoratoken import token
from utils import packer
from hashlib import sha256
from collections import OrderedDict


class AgoraTokenV6(token.AgoraToken):
    """
    | version(3B) | app id(32B) | Base64(
        | signature(str) | CRC(channel name)(4B) | CRC(Uid)(4B) | salt(4B) | ts(4B) | privilege(map) |
    ) |

    privileges = {}
    privileges[kPrivilegeJoinChannel] = int(time.time()) + 10 * 60
    ...
    """
    kVersion = '006'

    kPrivilegeJoinChannel = 1
    kPrivilegePublishAudioStream = 2
    kPrivilegePublishVideoStream = 3
    kPrivilegePublishDataStream = 4
    kPrivilegePublishAudioCdn = 5  # deprecated, unused
    kPrivilegePublishVideoCdn = 6  # deprecated, unused
    kPrivilegeRequestPublishAudioStream = 7  # deprecated, unused
    kPrivilegeRequestPublishVideoStream = 8  # deprecated, unused
    kPrivilegeRequestPublishDataStream = 9  # deprecated, unused
    kPrivilegeInvitePublishAudioStream = 10  # deprecated, unused
    kPrivilegeInvitePublishVideoStream = 11  # deprecated, unused
    kPrivilegeInvitePublishDataStream = 12  # deprecated, unused
    kPrivilegeAdministrateChannel = 101  # deprecated, unused
    kPrivilegeRtmLogin = 1000

    def __init__(self, app_id, app_cert):
        issue_ts = int(time.time())
        expired_ts = issue_ts + 24 * 60 * 60
        super(AgoraTokenV6, self).__init__(AgoraTokenV6.kVersion, app_id, app_cert, issue_ts, 0, expired_ts)

    def token(self, channel_name, uid, privileges):
        if not self.app_cert:
            return ''

        uid = '' if uid == 0 else str(uid)
        privileges = OrderedDict(sorted(iter(privileges.items()), key=lambda x: int(x[0])))

        m = packer.pack_uint32(self.salt) + packer.pack_uint32(self.expired_ts) + packer.pack_map_uint32(privileges)
        val = self.app_id.encode('utf-8') + channel_name.encode('utf-8') + uid.encode('utf-8') + m
        signature = hmac.new(self.app_cert.encode('utf-8'), val, sha256).digest()

        crc_channel_name = crc32(channel_name.encode('utf-8')) & 0xffffffff
        crc_uid = crc32(uid.encode('utf-8')) & 0xffffffff

        content = packer.pack_string(signature) + packer.pack_uint32(crc_channel_name) + packer.pack_uint32(crc_uid) + packer.pack_string(m)
        return self._version() + self.app_id + base64.b64encode(content).decode('utf-8')

    @staticmethod
    def analyze(key):
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
        except:
            return False, None, None, None, None, None, None, None
        return True, signature, app_id, cname_crc, uid_crc, ts, salt, privilege


