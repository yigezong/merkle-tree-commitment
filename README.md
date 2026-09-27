# 盲化 Merkle 树承诺

向量承诺：一次承诺绑定整条消息，打开任意一个位置只需要 O(log n) 的证明。哈希用的是按 FIPS 180-4 自行实现的 SHA-256，Merkle 树也是自己写的，不调用 `hashlib`，也不使用任何 Merkle 树库。

设计、binding / hiding 证明和实验数据在 [设计文档.md](设计文档.md)。

## 运行

需要 Python 3.10 或更高版本，没有第三方依赖。

```bash
python3 experiments.py
```

脚本会做四件事：

- 用 FIPS 180-4 的公开测试向量核对 SHA-256，包括 100 万个 `a`
- 检查诚实打开、篡改拒绝，以及建树时的哈希次数
- 做 hiding 和 binding 的对照实验
- 测量 commit / verify 的耗时，结果写到 `results/`

## 文件

| 文件 | 内容 |
|---|---|
| `mtc/sha256.py` | SHA-256 |
| `mtc/merkle.py` | 承诺、打开、验证 |
| `experiments.py` | 正确性、安全性实验、性能测试 |
| `设计文档.md` | 方案和安全性分析 |
| `results/` | 最近一次实验的数据和耗时图 |
