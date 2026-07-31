# kubezoo-controller

把上游集群对账成 Tenant 声明的样子:建租户的 namespace、发 RoleBinding、
把 ClusterRoleBinding 投影到各 namespace、派生集群级授权、执行停机。

依赖 [kubezoo-contract](https://github.com/fivetime/kubezoo-contract) 里的翻译规则 ——
它算出来的名字必须和 `kubezoo-proxy` 改写请求时算出来的**完全一致**。

## 为什么是独立进程

以前它跑在 kubezoo 进程的 post-start hook 里。那意味着**每一个 kubezoo 副本都跑一份控制器**,
三副本就是三份同时对账同一批租户。

apiserver 是**全活**的,控制器不是 —— k8s 自己把 `kube-apiserver` 和
`kube-controller-manager` 分成两个二进制,正是为了这件事。拆开之后,
"要几个代理"和"要几个控制器"才成为两个可以分别回答的问题。

⚠️ **部署后果**:只跑 `kubezoo-proxy` 的集群**能接受 Tenant 对象,但什么都不会发生** ——
没有 namespace,没有 RoleBinding。两个都要起。

## 运行

```
kubezoo-controller \
  --kubezoo-kubeconfig=/etc/kubezoo/zoo.kubeconfig \      # Tenant 对象在 kubezoo 里
  --upstream-kubeconfig=/etc/kubezoo/upstream.kubeconfig \ # 对账写到上游集群
  --client-ca-file=/etc/kubezoo/pki/ca.pem \
  --client-ca-key-file=/etc/kubezoo/pki/ca-key.pem \       # 要签租户证书,所以要私钥
  --kubezoo-address=kubezoo.example.com --kubezoo-port=6443
```

⚠️ **两个 kubeconfig 指向的是不同的集群**,别用同一个。

## ⛔ 现在只能跑一个副本

没有 leader 选举也没有分片。起两个就是两份控制器重复对账 —— 幂等的写不会互相破坏,
但**投影的孤儿清理在并发下没测过**。

终态应该是**按租户 ID 分片**而不是主从:租户之间完全独立,分片键是白送的,
而且主从只是把 informer 的内存**集中到一台**,分片才是**分摊**。
⚠️ 做之前要先解决:informer 按分片过滤(需要 shard 标签,否则每个副本还是得 watch 全部)、
重平衡期间的双主、以及验收必须是"实测负载真的分开了"。

## 测试

```
make test            # 单测 + 需要真 apiserver 的控制器测试
```
