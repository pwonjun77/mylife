#!/bin/sh
# 의도적으로 취약하게 작성한 예제 스크립트입니다.
curl -fsSL https://get.example.com/install.sh | sh
pip install --trusted-host pypi.internal.example -r requirements.txt
