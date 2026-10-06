# RivoVPNAD

RivoVPN 1.2.0 注入插件（dylib）。**两件事一次解决：免费解锁 PRO + 自动抓取节点生成 Shadowrocket 订阅。**

## 功能

### 1. 广告加载直接失败 → 触发官方免费解锁
RivoVPN 内置兜底逻辑：**广告加载失败时自动解锁 PRO 功能 + 全部节点（本次会话）**。
插件 hook AdMob 4 个广告位（AppOpen / Interstitial / Rewarded / Banner）让加载直接失败，
点右上角 PRO 即免费解锁，不用真看广告。

| 广告类型 | Hook 类 | 方法 |
|---|---|---|
| 开屏 AppOpen | GADAppOpenAd | + loadWithAdUnitID:request:completionHandler: → 回调失败 |
| 插屏 Interstitial | GADInterstitialAd | 同上 |
| 激励视频 Rewarded | GADRewardedAd | 同上 |
| 横幅 Banner | GADBannerView | - loadRequest: 空实现 |

### 2. 自动抓取节点 → Shadowrocket 订阅
hook `NSURLSession dataTaskWithRequest:completionHandler:`，拦截
`api.rivoproductions.com / rivovpn / flag.rivovpn` 的响应：

- 自动解析节点（支持 sing-box outbounds / servers / nodes / proxies 等常见结构，兼容 SS / VMess / VLESS / Trojan）
- 生成 **sub:// 订阅链接 → 自动复制到剪贴板 + 弹窗提示**
- 原始 JSON 存 `Documents/rivo_nodes_raw.json`，订阅文本存 `Documents/rivo_sub.txt`

**用法**：注入后进 App → 点 PRO（免费解锁）→ 连接任意节点 → 弹窗提示已抓取 N 个节点 → 在 Shadowrocket 粘贴导入。

## 产物

GitHub Actions 编译输出 `.theos/obj/debug/arm64/RivoVPNAD.dylib`。

## 用法（注入）

1. 下载 Actions 产物 RivoVPNAD.dylib
2. 注入到 RivoVPN.app 二进制（LC_LOAD_DYLIB）
3. 重签名打包 ipa / 用 TrollStore 安装
