#import <Foundation/Foundation.h>

#pragma mark - 广告屏蔽错误

static NSError *rivoAdBlockError(void) {
    return [NSError errorWithDomain:@"com.rivo.adblock"
                               code:1
                           userInfo:@{NSLocalizedDescriptionKey: @"Ad blocked by RivoVPNAD"}];
}

#pragma mark - AppOpen 开屏广告：加载直接失败，永不展示

%hook GADAppOpenAd
+ (void)loadWithAdUnitID:(id)adUnitID request:(id)request completionHandler:(id)handler {
    void (^completion)(id, NSError *) = handler;
    if (completion) {
        completion(nil, rivoAdBlockError());
    }
}
%end

#pragma mark - 插屏广告：加载直接失败，永不展示

%hook GADInterstitialAd
+ (void)loadWithAdUnitID:(id)adUnitID request:(id)request completionHandler:(id)handler {
    void (^completion)(id, NSError *) = handler;
    if (completion) {
        completion(nil, rivoAdBlockError());
    }
}
%end

#pragma mark - 激励视频：加载直接失败，永不展示

%hook GADRewardedAd
+ (void)loadWithAdUnitID:(id)adUnitID request:(id)request completionHandler:(id)handler {
    void (^completion)(id, NSError *) = handler;
    if (completion) {
        completion(nil, rivoAdBlockError());
    }
}
%end

#pragma mark - 横幅广告：空实现，永不加载

%hook GADBannerView
- (void)loadRequest:(id)request {
}
%end
