# Agora Token Helper

Only support AgoraToken version 001 - 006.

## 1 Analyzer

The analyzer can help you parse the original content of the AgoraToken, which you can use to check whether it is correct.

``` shell
# Example
python3 analyzer.py 006970CA35de60c44645bbae8a215061b33IACV0fZUBw+72cVoL9eyGGh3Q6Poi8bgjwVLnyKSJyOXR7dIfRBXoFHlEAABAAAAR/QQAAEAAQCvKDdW

# Output
## version:  006
## [AccessToken] Signature: 95d1f654070fbbd9c5682fd7b218687743a3e88bc6e08f054b9f229227239747, AppId: 970CA35de60c44645bbae8a215061b33, CRC(ChannelName): 276646071, CRC(Uid): 3847331927, Ts: 1111111, Salt: 1, privilege: 1:1446455471
```

