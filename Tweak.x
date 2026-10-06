#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// ===== RivoVPNAD v3: 延迟轮询 hook（解决 AdMob 类懒加载导致 hook 失效）=====

#pragma mark - 工具函数

static NSError *rivoAdBlockError(void) {
    return [NSError errorWithDomain:@"com.rivo.adblock"
                               code:1
                           userInfo:@{NSLocalizedDescriptionKey: @"Ad blocked by RivoVPNAD"}];
}

static BOOL rivoIsGADObject(id obj) {
    if (!obj) return NO;
    NSString *cls = NSStringFromClass([obj class]);
    if (!cls) return NO;
    return [cls hasPrefix:@"GAD"] || [cls hasPrefix:@"Google"];
}

static BOOL rivoIsTargetURL(NSString *url) {
    if (!url) return NO;
    return [url containsString:@"rivoproductions"] ||
           [url containsString:@"rivovpn"] ||
           [url containsString:@"flag.rivovpn"];
}

// 把单个节点字典转成 Shadowrocket URI
static NSString *rivoURIFromDict(NSDictionary *d) {
    NSString *name = d[@"name"] ?: d[@"remark"] ?: d[@"title"] ?: d[@"ps"] ?: @"rivo";
    NSString *host = d[@"server"] ?: d[@"host"] ?: d[@"address"] ?: d[@"addr"] ?: d[@"ip"];
    NSNumber *portN = d[@"port"];
    if (!host || !portN) return nil;
    NSString *port = [portN stringValue];
    NSString *uuid = d[@"uuid"] ?: d[@"id"] ?: d[@"password"];
    NSString *method = d[@"method"] ?: d[@"cipher"] ?: @"aes-128-gcm";
    NSString *passwd = d[@"password"] ?: d[@"key"];
    NSString *sni = d[@"sni"] ?: d[@"servername"] ?: d[@"serverName"] ?: d[@"host"];
    NSNumber *alterId = d[@"alterId"] ?: d[@"aid"];

    NSData *nameData = [name dataUsingEncoding:NSUTF8StringEncoding];
    NSString *nameB64 = [nameData base64EncodedStringWithOptions:0];

    if (uuid && passwd && [passwd length] > 0) {
        NSString *tp = [NSString stringWithFormat:@"%@:%@@%@:%@?peer=%@#%@",
                        uuid, passwd, host, port, sni ?: @"", nameB64];
        return [@"trojan://" stringByAppendingString:tp];
    }
    if (uuid) {
        if (alterId && [alterId intValue] > 0) {
            NSString *payload = [NSString stringWithFormat:@"%@:%@@%@:%@", uuid, method, host, port];
            NSDictionary *extra = @{@"alterId": alterId, @"sni": sni ?: @"", @"type": @"none"};
            NSData *jData = [NSJSONSerialization dataWithJSONObject:extra options:0 error:nil];
            NSString *jB64 = [[jData base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
            NSString *vp = [NSString stringWithFormat:@"%@?remarks=%@&obfsParam=%@", payload, nameB64, jB64];
            return [@"vmess://" stringByAppendingString:vp];
        }
        NSString *vp = [NSString stringWithFormat:@"%@:%@@%@:%@?encryption=none&security=tls&sni=%@#%@",
                        uuid, @"", host, port, sni ?: @"", nameB64];
        return [@"vless://" stringByAppendingString:vp];
    }
    if (passwd && method) {
        NSData *userinfo = [[NSString stringWithFormat:@"%@:%@", method, passwd] dataUsingEncoding:NSUTF8StringEncoding];
        NSString *uiB64 = [[userinfo base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
        return [NSString stringWithFormat:@"ss://%@@%@:%@#%@", uiB64, host, port, nameB64];
    }
    return nil;
}

// 递归收集节点
static void rivoCollectNodes(id obj, NSMutableArray *uris, int depth) {
    if (!obj || depth > 6) return;
    if ([obj isKindOfClass:[NSArray class]]) {
        for (id item in (NSArray *)obj) {
            rivoCollectNodes(item, uris, depth + 1);
        }
    } else if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *d = (NSDictionary *)obj;
        for (NSString *key in @[@"outbounds", @"nodes", @"servers", @"serverList", @"list", @"proxies", @"configs", @"data"]) {
            id val = d[key];
            if ([val isKindOfClass:[NSArray class]]) {
                for (id item in (NSArray *)val) {
                    if ([item isKindOfClass:[NSDictionary class]]) {
                        NSString *uri = rivoURIFromDict((NSDictionary *)item);
                        if (uri) [uris addObject:uri];
                    } else {
                        rivoCollectNodes(item, uris, depth + 1);
                    }
                }
            }
        }
        NSString *uri = rivoURIFromDict(d);
        if (uri && ![uris containsObject:uri]) [uris addObject:uri];
    }
}

static void rivoShowAlert(NSString *title, NSString *msg) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIApplication *app = [UIApplication sharedApplication];
        UIWindow *win = nil;
        for (UIWindow *w in app.windows) {
            if (w.isKeyWindow) { win = w; break; }
        }
        if (!win) win = app.windows.firstObject;
        UIViewController *root = win.rootViewController;
        if (!root) return;
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
        [root presentViewController:ac animated:YES completion:nil];
    });
}

static void rivoSaveNodes(NSData *data, NSString *url) {
    if (!data.length) return;
    NSError *err = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
    if (err || !obj) return;
    NSMutableArray *uris = [NSMutableArray array];
    rivoCollectNodes(obj, uris, 0);

    NSString *home = NSHomeDirectory();
    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    NSString *rawPath = [docDir stringByAppendingPathComponent:@"rivo_nodes_raw.json"];
    [data writeToFile:rawPath atomically:YES];

    if (uris.count == 0) {
        NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        UIPasteboard *pb = [UIPasteboard generalPasteboard];
        pb.string = raw;
        rivoShowAlert(@"RivoVPNAD", [NSString stringWithFormat:@"已复制原始数据(%lu字节)到剪贴板，节点结构待适配\n%@", (unsigned long)data.length, url]);
        return;
    }

    NSString *subText = [uris componentsJoinedByString:@"\n"];
    NSData *subData = [subText dataUsingEncoding:NSUTF8StringEncoding];
    NSString *subB64 = [[subData base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
    NSString *subLink = [@"sub://" stringByAppendingString:subB64];

    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    pb.string = subLink;

    [subText writeToFile:[docDir stringByAppendingPathComponent:@"rivo_sub.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];

    rivoShowAlert(@"RivoVPNAD", [NSString stringWithFormat:@"已抓取 %lu 个节点，订阅链接已复制到剪贴板\nShadowrocket 中粘贴即可导入", (unsigned long)uris.count]);
}

#pragma mark - 方案 A：广告加载直接失败（触发官方免费解锁）

static void rivoFailFullScreenLoad(id self, SEL _cmd, id adUnitID, id request, id handler) {
    void (^completion)(id, NSError *) = handler;
    if (completion) completion(nil, rivoAdBlockError());
}

static void rivoEmptyBannerLoad(id self, SEL _cmd, id request) {
}

#pragma mark - 展示层兜底拦截（Banner / 原生广告）

static void rivoAddSubview(id self, SEL _cmd, id view) {
    static IMP origImp = NULL;
    if (!origImp) origImp = method_getImplementation(class_getInstanceMethod([UIView class], @selector(addSubview:)));
    if (rivoIsGADObject(view)) {
        ((UIView *)view).hidden = YES;
    }
    ((void (*)(id, SEL, id))origImp)(self, _cmd, view);
}

#pragma mark - 节点抓取：hook NSURLSession

static IMP origDataTaskIMP = NULL;

static id rivoDataTask(id self, SEL _cmd, NSURLRequest *req, id completion) {
    NSString *u = req.URL.absoluteString;
    if (rivoIsTargetURL(u)) {
        void (^origComp)(NSData *, NSURLResponse *, NSError *) = completion;
        void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
            if (origComp) origComp(data, resp, err);
            if (data.length) rivoSaveNodes(data, u);
        };
        return ((id (*)(id, SEL, id, id))origDataTaskIMP)(self, _cmd, req, wrapped);
    }
    return ((id (*)(id, SEL, id, id))origDataTaskIMP)(self, _cmd, req, completion);
}

#pragma mark - 执行 hook（AdMob 类懒加载 → 延迟轮询）

static void rivoDoHook(void) {
    // 1) AdMob 全屏广告：加载直接失败
    Class gAppOpen = NSClassFromString(@"GADAppOpenAd");
    Class gInter = NSClassFromString(@"GADInterstitialAd");
    Class gRew = NSClassFromString(@"GADRewardedAd");
    Class gBanner = NSClassFromString(@"GADBannerView");

    SEL loadSel = NSSelectorFromString(@"loadWithAdUnitID:request:completionHandler:");
    if (gAppOpen) {
        Method m = class_getClassMethod(gAppOpen, loadSel);
        if (m) method_setImplementation(m, (IMP)rivoFailFullScreenLoad);
    }
    if (gInter) {
        Method m = class_getClassMethod(gInter, loadSel);
        if (m) method_setImplementation(m, (IMP)rivoFailFullScreenLoad);
    }
    if (gRew) {
        Method m = class_getClassMethod(gRew, loadSel);
        if (m) method_setImplementation(m, (IMP)rivoFailFullScreenLoad);
    }
    if (gBanner) {
        Method m = class_getInstanceMethod(gBanner, @selector(loadRequest:));
        if (m) method_setImplementation(m, (IMP)rivoEmptyBannerLoad);
    }

    // 2) 展示层兜底：GAD 视图挂载即隐藏
    Method ma = class_getInstanceMethod([UIView class], @selector(addSubview:));
    if (ma) method_setImplementation(ma, (IMP)rivoAddSubview);

    // 3) 节点抓取：NSURLSession 响应拦截
    Method md = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
    if (md) {
        origDataTaskIMP = method_getImplementation(md);
        method_setImplementation(md, (IMP)rivoDataTask);
    }
}

static void rivoTryHook(int attempt) {
    Class gRew = NSClassFromString(@"GADRewardedAd");
    Class gBanner = NSClassFromString(@"GADBannerView");
    if (gRew || gBanner || attempt >= 15) {
        rivoDoHook();
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
                       rivoTryHook(attempt + 1);
                   });
}

__attribute__((constructor)) static void rivoInit(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
                       rivoTryHook(0);
                   });
}
