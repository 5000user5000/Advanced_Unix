FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 安裝常用套件
RUN apt-get update && apt-get install -y \
    build-essential gdb vim git wget curl python3 \
    libcapstone-dev iproute2 net-tools strace \
    libssl-dev zlib1g-dev libelf-dev pkg-config \
    ca-certificates sudo

# 安裝 pwndbg（推薦使用這個而不是 peda/pwngdb）
RUN git clone https://github.com/pwndbg/pwndbg /opt/pwndbg && \
    cd /opt/pwndbg && ./setup.sh

# 建立預設工作目錄
WORKDIR /workspace

# 顯示提示
CMD echo "🟢 Welcome to UP25 HW1 Docker environment!" && bash
