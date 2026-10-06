#import <UIKit/UIKit.h>

#pragma mark - 工具：判断是否为 AdMob(GAD) 相关对象

static BOOL rivoIsGADObject(id obj) {
    if (!obj) return NO;
    NSString *cls = NSStringFromClass([obj class]);
    if (!cls) return NO;
    return [cls hasPrefix:@"GAD"] || [cls hasPrefix:@"Google"];
}

#pragma mark - 全屏广告（开屏 AppOpen / 插屏 / 激励视频）：
// AdMob 全屏广告展示统一走 [UIViewController presentViewController:animated:completion:]，
// 广告控制器类名以 GAD 开头。识别到就直接忽略，广告正常加载但永远弹不出来。

%hook UIViewController
- (void)presentViewController:(UIViewController *)viewControllerToPresent animated:(BOOL)flag completion:(void (^)(void))completion {
    if (rivoIsGADObject(viewControllerToPresent)) {
        if (completion) completion();
        return;
    }
    %orig;
}
%end

#pragma mark - 横幅 / 原生广告：
# GADBannerView、GADNativeAdView 等广告视图以 GAD 开头，被 addSubview 挂到界面上时
# 直接标记 hidden，广告正常加载但肉眼不可见。

%hook UIView
- (void)addSubview:(UIView *)view {
    if (rivoIsGADObject(view)) {
        view.hidden = YES;
    }
    %orig;
}
%end
