#!/usr/bin/env bash
# 在本机起一个租户控制器,对着已经跑起来的 kubezoo 和上游集群。
#
# 单独调控制器时可以直接用;kubezoo-proxy 的 hack/lab/up.sh 也调它 —— 那边
# 不该再抄一份怎么起控制器,抄了就会漂移。
#
# 用法:  up-controller.sh <工作目录> <kubezoo-kubeconfig> <upstream-kubeconfig> <CA目录> [kubezoo地址] [端口]
set -euo pipefail

LAB=${1:?用法见文件头}
ZOO_KUBECONFIG=${2:?需要一个能连到 kubezoo 的 kubeconfig}
UPSTREAM_KUBECONFIG=${3:?需要一个能连到上游集群的 kubeconfig}
PKI=${4:?需要 kubezoo 的 CA 目录(要 ca.pem 和 ca-key.pem)}
ZOO_ADDRESS=${5:-127.0.0.1}
ZOO_PORT=${6:-6443}

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
mkdir -p "$LAB"

( cd "$HERE" && go build -o "$LAB/kubezoo-controller" ./cmd/kubezoo-controller )

# ⚠️ 控制器只能跑一个:没有 leader 选举也没有分片。先把旧的收掉,否则重跑一次
# lab 就变成两份控制器对账同一批租户 —— 而那正是没测过的情形。
pgrep -f "$LAB/kubezoo-controller" | xargs -r kill 2>/dev/null || true

nohup "$LAB/kubezoo-controller" \
  --kubezoo-kubeconfig="$ZOO_KUBECONFIG" \
  --upstream-kubeconfig="$UPSTREAM_KUBECONFIG" \
  --client-ca-file="$PKI/ca.pem" --client-ca-key-file="$PKI/ca-key.pem" \
  --kubezoo-address="$ZOO_ADDRESS" --kubezoo-port="$ZOO_PORT" \
  >"$LAB/kubezoo-controller.log" 2>&1 &

for _ in $(seq 30); do
  grep -q "kubezoo-controller running" "$LAB/kubezoo-controller.log" 2>/dev/null && break
  sleep 1
done
if ! pgrep -f "$LAB/kubezoo-controller" >/dev/null; then
  echo "FATAL: kubezoo-controller 没能留住:" >&2
  tail -5 "$LAB/kubezoo-controller.log" >&2
  exit 1
fi
echo "kubezoo-controller: up"
