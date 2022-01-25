# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"


from agoratoken import token_v1
from agoratoken import token_v2
from agoratoken import token_v3
from agoratoken import token_v4
from agoratoken import token_v5
from agoratoken import token_v6


# token ttl in seconds, should not set for particularly long periods of time.
# if token expired, the client needs to send a request to the server to get a new one.
# the server should check the user's permission, and do not assign too much privilege.
MAX_TTL = 5 * 60


def generate_token_v1(app_id, app_cert, **kwargs):
    params = dict(kwargs)
    channel_name = params.get('channel_name', '')
    if not channel_name:
        return False, {'reason': 'Request parameter error, "channel_name" empty'}

    generator = token_v1.AgoraTokenV1(app_id, app_cert, 0, 0)
    return True, {'channel_name': channel_name, 'token': generator.token(channel_name)}


def generate_token_v2(app_id, app_cert, **kwargs):
    params = dict(kwargs)
    channel_name = params.get('channel_name', '')
    uid = params.get('uid', '')
    if not channel_name and not uid:
        return False, {'reason': 'Request parameter error, "channel_name" and "uid" both empty'}

    expired_ts = int(params.get('expired_ts', MAX_TTL))
    generator = token_v2.AgoraTokenV2(app_id, app_cert, 0, 0, expired_ts)
    return True, {'channel_name': channel_name, 'uid': uid, 'token': generator.token(channel_name, uid)}


def generate_token_v3(app_id, app_cert, **kwargs):
    params = dict(kwargs)
    channel_name = params.get('channel_name', '')
    uid = params.get('uid', '')
    if not channel_name and not uid:
        return False, {'reason': 'Request parameter error, "channel_name" and "uid" both empty'}

    expired_ts = int(params.get('expired_ts', MAX_TTL))
    generator = token_v3.AgoraTokenV3(app_id, app_cert, 0, 0, expired_ts)
    return True, {'channel_name': channel_name, 'uid': uid, 'token': generator.token(channel_name, uid)}


def generate_token_v4(app_id, app_cert, **kwargs):
    params = dict(kwargs)
    channel_name = params.get('channel_name', '')
    uid = params.get('uid', '')
    if not channel_name and not uid:
        return False, {'reason': 'Request parameter error, "channel_name" and "uid" both empty'}

    service_type = params.get('service_type', '')
    if not service_type:
        return False, {'reason': 'Request parameter error, "service_type" empty'}

    expired_ts = int(params.get('expired_ts', MAX_TTL))
    generator = token_v4.AgoraTokenV4(app_id, app_cert, 0, 0, expired_ts)
    return True, {'channel_name': channel_name, 'uid': uid, 'token': generator.token(channel_name, uid, service_type)}


def generate_token_v5(app_id, app_cert, **kwargs):
    params = dict(kwargs)
    channel_name = params.get('channel_name', '')
    uid = params.get('uid', '')
    if not channel_name and not uid:
        return False, {'reason': 'Request parameter error, "channel_name" and "uid" both empty'}

    service_type = params.get('service_type', '')
    if not service_type:
        return False, {'reason': 'Request parameter error, "service_type" empty'}

    try:
        service_type = int(service_type)
    except:
        return False, {'reason': 'Request parameter error, "service_type" should be integer'}

    expired_ts = int(params.get('expired_ts', MAX_TTL))
    generator = token_v5.AgoraTokenV5(app_id, app_cert, 0, 0, expired_ts)

    extra_info = {}
    if 'mic' not in params or str(params['mic']).lower() != 'false':
        extra_info[token_v5.AgoraTokenV5.kExtraInfoAllowUploadInChannel] = \
            token_v5.AgoraTokenV5.kPermisionAudioVideoUpload
    return True, {'channel_name': channel_name, 'uid': uid, 'token': generator.token(channel_name, uid, service_type, extra_info)}


def generate_token_v6(app_id, app_cert, **kwargs):
    params = dict(kwargs)
    channel_name = params.get('channel_name', '')
    uid = params.get('uid', '')
    if not channel_name and not uid:
        return False, {'reason': 'Request parameter error, "channel_name" and "uid" both empty'}

    expired_ts = int(params.get('expired_ts', MAX_TTL))
    privilege = {int(i): expired_ts for i in params['privilege']} if 'privilege' in params else {}
    if 'mic' not in params or str(params['mic']).lower() != 'false':
        privilege[token_v6.AgoraTokenV6.kPrivilegeJoinChannel] = expired_ts
        privilege[token_v6.AgoraTokenV6.kPrivilegePublishAudioStream] = expired_ts
        privilege[token_v6.AgoraTokenV6.kPrivilegePublishVideoStream] = expired_ts
        privilege[token_v6.AgoraTokenV6.kPrivilegePublishDataStream] = expired_ts

    generator = token_v6.AgoraTokenV6(app_id, app_cert)
    return True, {'channel_name': channel_name, 'uid': uid, 'token': generator.token(channel_name, uid, privilege)}


def generate_token(app_id, app_cert, version, **kwargs):
    params = dict(kwargs)
    response = {'app_id': app_id, 'token': ''}
    if 'tag' in params:
        response['tag'] = params['tag']

    version_hanlder = {
        # these version are unsafe, should not be used
        # '1': generate_token_v1,
        # '2': generate_token_v2,
        # '3': generate_token_v3,
        # '4': generate_token_v4,
        # '5': generate_token_v5,
        '6': generate_token_v6,
    }
    if version not in version_hanlder:
        return False, {'reason': 'Request token version {} not supported'.format(version)}

    ok, info = version_hanlder[version](app_id, app_cert, **params)
    response.update(info)
    return ok, response

