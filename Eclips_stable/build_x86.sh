#!/bin/sh
set -e
NDK="${NDK:-/opt/android-ndk-r26d}"
sed -i.bak 's/^APP_ABI[[:space:]]*:=.*/APP_ABI      := x86_64/' Application.mk
"$NDK/ndk-build" NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk NDK_APPLICATION_MK=Application.mk -j4
mv -f Application.mk.bak Application.mk 2>/dev/null || true
mkdir -p bin && cp libs/x86_64/eclipsoxide bin/eclipsoxide_x86_64
echo "OK -> bin/eclipsoxide_x86_64"
