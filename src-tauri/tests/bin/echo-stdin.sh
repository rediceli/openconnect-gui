#!/bin/sh
# 测试替身：忽略所有 argv，只把 stdin 原样吐到 stdout。
# ArgPlan 总会把 server 作为位置参数追加进来，所以不能直接用 /bin/cat
# （它会把 --passwd-on-stdin 当成选项）。
exec cat
