# Agora Token Helper

Support AgoraToken version 001 - 006. But for security reasons, I recommend using version 006 and above.

## 1 Analyzer

The analyzer can help you parse the original content of the AgoraToken, which you can use to check whether it is correct.

``` shell
# Example(appID: 970CA35de60c44645bbae8a215061b33, appCert: 5CFd2fd1755d40ecb72977518be15d3b)
python3 analyzer.py 006970CA35de60c44645bbae8a215061b33IACV0fZUBw+72cVoL9eyGGh3Q6Poi8bgjwVLnyKSJyOXR7dIfRBXoFHlEAABAAAAR/QQAAEAAQCvKDdW

# Output
## version:  006
## [AccessToken] Signature: 95d1f654070fbbd9c5682fd7b218687743a3e88bc6e08f054b9f229227239747, AppId: 970CA35de60c44645bbae8a215061b33, CRC(ChannelName): 276646071, CRC(Uid): 3847331927, Ts: 1111111, Salt: 1, privilege: 1:1446455471
```

## 2 Checker

If you want to use a checker, you need to modify the `configs/project.json` file and set the parameters in the file to the one used by the current generated AgoraToken.

``` shell
# Example(appID: 970CA35de60c44645bbae8a215061b33, appCert: 5CFd2fd1755d40ecb72977518be15d3b)
python3 checker.py 006970CA35de60c44645bbae8a215061b33IACV0fZUBw+72cVoL9eyGGh3Q6Poi8bgjwVLnyKSJyOXR7dIfRBXoFHlEAABAAAAR/QQAAEAAQCvKDdW -c 7d72365eb983485397e3e3f9d460bdda -u 2882341273

# Output
## version:  006
## [AccessToken] Signature: 95d1f654070fbbd9c5682fd7b218687743a3e88bc6e08f054b9f229227239747, AppId: 970CA35de60c44645bbae8a215061b33, CRC(ChannelName): 276646071, CRC(Uid): 3847331927, Ts: 1111111, Salt: 1, privilege: 1:1446455471
## [Check] Error: token expired, now ts: 1642995315, expired at 1111111
## [Check] Error: token privilege expired, privilege: 1, now ts: 1642995315, expired at 1446455471

# -----------------------------------
# Example use wrong channel and user id(appID: 970CA35de60c44645bbae8a215061b33, appCert: 5CFd2fd1755d40ecb72977518be15d3b)
python3 checker.py 006970CA35de60c44645bbae8a215061b33IACV0fZUBw+72cVoL9eyGGh3Q6Poi8bgjwVLnyKSJyOXR7dIfRBXoFHlEAABAAAAR/QQAAEAAQCvKDdW -c abc -u 123

# Output
## version:  006
## [AccessToken] Signature: 95d1f654070fbbd9c5682fd7b218687743a3e88bc6e08f054b9f229227239747, AppId: 970CA35de60c44645bbae8a215061b33, CRC(ChannelName): 276646071, CRC(Uid): 3847331927, Ts: 1111111, Salt: 1, privilege: 1:1446455471
## [Check] Error: token expired, now ts: 1642995508, expired at 1111111
## [Check] Error: token privilege expired, privilege: 1, now ts: 1642995508, expired at 1446455471
## [Check] Error: channel name crc32 not same
## [Check] Error: user id crc32 not same
## [Check] Error: signature not same
```
