# RivoVPNAD

RivoVPN 1.2.0 广告拦截插件（dylib）。

## 拦截范围

| 广告类型 | Hook 类 | 方法 |
|---|---|---|
| 开屏 AppOpen | GADAppOpenAd | + loadWithAdUnitID:request:completionHandler: |
| 插屏 Interstitial | GADInterstitialAd | + loadWithAdUnitID:request:completionHandler: |
| 激励视频 Rewarded | GADRewardedAd | + loadWithAdUnitID:request:completionHandler: |
| 横幅 Banner | GADBannerView | - loadRequest: |

## 原理

全部是 AdMob 官方 Objective-C 类。hook 后让广告**加载直接失败**（completionHandler 回调错误 / 空实现），App 走正常失败流程不会崩溃，广告永不展示。

mediation 子网络（UnityAds / Vungle / AppLovin 等）都走 AdMob 网关分发，拦死 AdMob 即全部拦死。

## 产物

GitHub Actions 编译输出 `.theos/obj/debug/arm64/RivoVPNAD.dylib`。

## 用法

1. 下载 Actions 产物 RivoVPNAD.dylib
2. 注入到 RivoVPN.app 二进制（LC_LOAD_DYLIB）
3. 重签名打包 ipa
