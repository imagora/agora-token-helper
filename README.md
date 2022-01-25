# Agora Token Helper

Support AgoraToken version 001 - 006. But for security reasons, I recommend using version 006 and above.

## 1 Analyzer

The analyzer can help you parse the original content of the AgoraToken, which you can use to check whether it is correct.

``` shell
# Example(appID: 970CA35de60c44645bbae8a215061b33, appCert: 5CFd2fd1755d40ecb72977518be15d3b)
python3 analyzer.py 006970CA35de60c44645bbae8a215061b33IACV0fZUBw+72cVoL9eyGGh3Q6Poi8bgjwVLnyKSJyOXR7dIfRBXoFHlEAABAAAAR/QQAAEAAQCvKDdW

# Output
## version:  006
## [Analyze] AccessToken(V6), Signature: 95d1f654070fbbd9c5682fd7b218687743a3e88bc6e08f054b9f229227239747, AppId: 970CA35de60c44645bbae8a215061b33, CRC(ChannelName): 276646071, CRC(Uid): 3847331927, Ts: 1111111, Salt: 1, privilege: 1:1446455471
```

## 2 Checker

If you want to use a checker, you need to modify the `configs/project.json` file and set the parameters in the file to the one used by the current generated AgoraToken.

``` shell
# Example(appID: 970CA35de60c44645bbae8a215061b33, appCert: 5CFd2fd1755d40ecb72977518be15d3b)
python3 checker.py 006970CA35de60c44645bbae8a215061b33IACV0fZUBw+72cVoL9eyGGh3Q6Poi8bgjwVLnyKSJyOXR7dIfRBXoFHlEAABAAAAR/QQAAEAAQCvKDdW -c 7d72365eb983485397e3e3f9d460bdda -u 2882341273

# Output
## version:  006
## [Check] AccessToken(V6), Signature: 95d1f654070fbbd9c5682fd7b218687743a3e88bc6e08f054b9f229227239747, AppId: 970CA35de60c44645bbae8a215061b33, CRC(ChannelName): 276646071, CRC(Uid): 3847331927, Ts: 1111111, Salt: 1, privilege: 1:1446455471
## [Check] Error: token expired, now ts: 1642995315, expired at 1111111
## [Check] Error: token privilege expired, privilege: 1, now ts: 1642995315, expired at 1446455471

# -----------------------------------
# Example use wrong channel and user id(appID: 970CA35de60c44645bbae8a215061b33, appCert: 5CFd2fd1755d40ecb72977518be15d3b)
python3 checker.py 006970CA35de60c44645bbae8a215061b33IACV0fZUBw+72cVoL9eyGGh3Q6Poi8bgjwVLnyKSJyOXR7dIfRBXoFHlEAABAAAAR/QQAAEAAQCvKDdW -c abc -u 123

# Output
## version:  006
## [Check] AccessToken(V6), Signature: 95d1f654070fbbd9c5682fd7b218687743a3e88bc6e08f054b9f229227239747, AppId: 970CA35de60c44645bbae8a215061b33, CRC(ChannelName): 276646071, CRC(Uid): 3847331927, Ts: 1111111, Salt: 1, privilege: 1:1446455471
## [Check] Error: token expired, now ts: 1642995508, expired at 1111111
## [Check] Error: token privilege expired, privilege: 1, now ts: 1642995508, expired at 1446455471
## [Check] Error: channel name crc32 not same
## [Check] Error: user id crc32 not same
## [Check] Error: signature not same
```

You also need to pay attention to whether the privilege settings are correct, which cannot be judged from the token alone.
For example, a user who has no privilege cannot send any audio, video, etc.

## 3 Server

**Attention:**
1. this is a very simple example service that you need to rewrite and check user's permissions very carefully!
2. need to follow the actual business needs and don't assign user too much privilege!
3. pay attention to the token ttl, don't assign a high permissions(audio, video, etc.) for a long time!
4. should also think about the risk of AppCert leaks, which should consider a regularly updates to AppCert, and a blue-green replacement strategy.

