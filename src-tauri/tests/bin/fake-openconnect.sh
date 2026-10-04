#!/bin/sh
# openconnect 的长驻替身：读完 stdin 后一直跑到收到 SIGINT。
# 用于测试 Stop 路径（SIGINT → 正常退出），因为 mock gateway
# 会在 CONNECT 阶段立刻失败，隧道活不到能测断开的时刻。
trap 'exit 0' INT
cat > /dev/null
while : ; do sleep 0.2; done
