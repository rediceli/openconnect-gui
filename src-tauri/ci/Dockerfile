# Linux 特权边界测试容器
#
# 构建：
#   docker build -f ci/Dockerfile -t wthinkvpn-ci src-tauri
# 运行：
#   docker run --rm --privileged wthinkvpn-ci
#
# 刻意用 Debian 而不是 Alpine：polkit + pkexec + shadow（useradd）
# 在 Alpine 上要么没有要么行为不同，会掩盖真实发行版上的问题。

FROM rust:1-bookworm

# polkit 提供 pkaction/pkexec；sudo 供 privsep-test.sh 用；
# python3 供脚本内的 socket 客户端；procps/net-tools 便于排查。
RUN apt-get update && apt-get install -y --no-install-recommends \
        policykit-1 \
        sudo \
        python3 \
        procps \
        iproute2 \
        dbus \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 测试需要 openconnect 存在（虽然只验证它被拒绝而非执行）
RUN apt-get update && apt-get install -y --no-install-recommends \
        openconnect \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY . /work

RUN chmod +x ci/privsep-test.sh ci/run-in-docker.sh helper/install.sh

# polkitd 需要一个 session bus 才能工作
ENV DBUS_SESSION_BUS_ADDRESS=/dev/null
ENTRYPOINT ["/work/ci/run-in-docker.sh"]