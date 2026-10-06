# RivoVPNAD

RivoVPN 1.2.0 广告拦截插件（dylib）。**方案 B：广告正常加载、拦截展示层**——Google 后台看到正常填充，广告只是永不显示。

## 拦截范围

| 广告类型 | Hook 类 | 方法 | 机制 |
|---|---|---|---|
| 开屏 AppOpen | UIViewController | - presentViewController:animated:completion: | 识别 GAD 广告控制器直接忽略（不弹出） |
| 插屏 Interstitial | 同上 | 同上 | 同上 |
| 激励视频 Rewarded | 同上 | 同上 | 同上 |
| 横幅 Banner | UIView | - addSubview: | GAD 广告视图挂载时标记 hidden |
| 原生广告 Native | UIView | - addSubview: | 同上 |

## 原理

AdMob 全屏广告展示统一走 `presentViewController:`，广告控制器类名以 `GAD` 开头；Banner / 原生广告是 `GAD` 开头的 UIView。插件识别到就忽略展示 / 强制隐藏，**广告请求与填充完全正常**，无异常数据上报，不易被反作弊识别。

mediation 子网络（UnityAds / Vungle / AppLovin 等）都走 AdMob 网关分发，最终都经 AdMob 展示路径，一并被拦。

## 产物

GitHub Actions 编译输出 `.theos/obj/debug/arm64/RivoVPNAD.dylib`。

## 用法

1. 下载 Actions 产物 RivoVPNAD.dylib
2. 注入到 RivoVPN.app 二进制（LC_LOAD_DYLIB）
3. 重签名打包 ipa
