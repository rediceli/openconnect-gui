#!/bin/sh
# 测试替身：把 argv 一行一个打到 stdout。
for a in "$@"; do
  echo "arg: $a"
done
exec cat
