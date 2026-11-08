# YIFile 本地解密下载 — Gopeed 扩展

安卓/桌面 Gopeed 直接拉取 yifile CDN 密文, 在**设备本地**解密后落盘。
服务器零流量; 手机浏览器官方解密用不了, 走这个扩展即可。

## 原理

解析页返回的 YIFile 链接形如:

```
https://www.yifile.com/down.html#url=<CDN密文链接>&k=<密钥>&name=<文件名>
```

官方 down.html 的解密算法(本扩展 1:1 复刻):

- 密文 = AES-256-CTR, 每 50 MiB 一个分片
- `key = SHA-256("PWD|" + k)` (32 字节)
- `counter 基 = SHA-256("CTR|" + k)` 前 16 字节; 分片 c 内第 b 块 → 低 4 字节 = `be32(c + b)`
- 解出后即原始文件(7z/rar/zip…)

扩展通过 `gopeed.runtime.blob.createObjectURL(流工厂, {size, range:true})` 把明文流交给
Gopeed 核心: CDN 支持 `Range` 分段, 所以 Gopeed 多线程分段拉密文 → 扩展逐段解密 →
核心存盘。支持暂停/恢复/重试(每次重连都是无状态的 Range 请求)。

## 版本要求(重要)

`gopeed.runtime.blob.createObjectURL`(blob 数据流接管)是 2026-07-14 才合入
Gopeed main 分支的新 API(#1407), **v1.9.3 及更早的正式版不支持**。

- 需要: main 分支 2026-07-14 之后的构建, 或之后发布的正式版(≥ v1.9.4)
- 判断方法: 用本扩展解析一个 yifile 链接, 若报"不支持 blob 数据流 API"就是版本太老

## 安装

1. 打包(Windows PowerShell, 在扩展目录执行):
   ```powershell
   .\build.ps1
   ```
   生成 `frontend/dist/gopeed/gopeed-yifile.zip`(若网站托管了 `frontend/`, 则安装地址为
   `https://<你的域名>/dist/gopeed/gopeed-yifile.zip`)。

2. Gopeed 里安装: 设置 → 扩展 → 添加 → 从 URL 安装(粘贴 zip 地址), 或直接把 zip 放到
   Gopeed 的扩展目录后重启。

3. 使用: 解析页复制 YIFile 下载链接(down.html 开头的那条) → 打开 Gopeed 新建任务粘贴
   → 扩展自动接管, 显示原文件名与大小, 下载时在设备本地解密。

## 验证(可选)

Node.js 18+ 环境:

```powershell
node test.js            # 离线: SHA-256/AES 向量 + 跨 50MB 分片边界 + 流式解密
node test.js --live     # 在线: 用真实 CDN 链接验证(需要先把 test.js 里的 URL/k 换成有效值)
```

## 已知限制

- 解密速度受纯 JS AES 限制: 桌面几十 MB/s, 手机几 MB/s, 大文件会跑几分钟(后台可接受)。
- 只处理 `down.html#url=&k=` 形式; 分享页 `yifile.com/f/xxx` 仍需服务器账号解析。
