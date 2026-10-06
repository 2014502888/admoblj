#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

// ===== RivoVPNAD v6: 广告hook保留 + NSURLProtocol抓取 + LibboxSetup明文配置抓取 =====
// v6 新增：hook sing-box gomobile 的 LibboxSetup，抓 options.baseConfig（完整明文配置 JSON，
// 含全部 outbounds 节点），落盘 rivo_config.json 供验证；同时生成 Shadowrocket 订阅。

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
    return [cls hasPrefix:@"GAD"] || [cls hasPrefix:@"Google"] || [cls hasPrefix:@"Unity"];
}

static BOOL rivoIsTargetURL(NSString *url) {
    if (!url) return NO;
    return [url containsString:@"rivoproductions"] ||
           [url containsString:@"rivovpn"] ||
           [url containsString:@"flag.rivovpn"];
}

static void rivoAppendLog(NSString *fmt, ...) {
    @try {
        va_list args;
        va_start(args, fmt);
        NSString *line = [[NSString alloc] initWithFormat:fmt arguments:args];
        va_end(args);
        NSString *home = NSHomeDirectory();
        NSString *logPath = [home stringByAppendingPathComponent:@"Documents/rivo_debug.log"];
        NSString *stamp = [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                         dateStyle:NSDateFormatterShortStyle
                                                         timeStyle:NSDateFormatterMediumStyle];
        NSString *entry = [NSString stringWithFormat:@"[%@] %@\n", stamp, line];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
        if (!fh) {
            [entry writeToFile:logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } else {
            [fh seekToEndOfFile];
            [fh writeData:[entry dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
    } @catch (NSException *e) {
    }
}

// 转码 base64 的 tag 名（Shadowrocket 兼容）
static NSString *rivoTagName(NSString *name) {
    if (!name.length) name = @"rivo";
    NSData *d = [name dataUsingEncoding:NSUTF8StringEncoding];
    return [d base64EncodedStringWithOptions:0];
}

// sing-box outbound 字典 -> Shadowrocket URI
static NSString *rivoURIFromSingbox(NSDictionary *d) {
    NSString *type = d[@"type"];
    if (!type) return nil;
    if ([type isEqualToString:@"selector"] || [type isEqualToString:@"urltest"] ||
        [type isEqualToString:@"direct"] || [type isEqualToString:@"block"] ||
        [type isEqualToString:@"dns"] || [type isEqualToString:@"reject"] ||
        [type isEqualToString:@"loopback"] || [type isEqualToString:@"wireguard"] ||
        [type isEqualToString:@"hysteria2"] || [type isEqualToString:@"tuic"] ||
        [type isEqualToString:@"http"] || [type isEqualToString:@"socks"] ||
        [type isEqualToString:@"shadowtls"]) {
        return nil;
    }
    NSString *server = d[@"server"];
    NSNumber *portN = d[@"server_port"] ?: d[@"port"];
    if (!server || !portN) return nil;
    NSString *port;
    if ([portN isKindOfClass:[NSNumber class]]) {
        port = [portN stringValue];
    } else if ([portN isKindOfClass:[NSString class]]) {
        port = (NSString *)portN;
    } else {
        return nil;
    }
    NSString *name = rivoTagName(d[@"tag"] ?: @"rivo");
    NSDictionary *tls = d[@"tls"];
    NSString *sni = tls[@"server_name"] ?: tls[@"serverName"];
    NSString *uuid = d[@"uuid"];
    NSString *password = d[@"password"];
    NSString *method = d[@"method"] ?: @"aes-128-gcm";

    if ([type isEqualToString:@"vless"]) {
        NSString *flow = d[@"flow"];
        NSString *q = [NSString stringWithFormat:@"encryption=none&security=tls&sni=%@&fp=chrome&type=tcp",
                       sni ?: @""];
        if (flow.length) q = [q stringByAppendingFormat:@"&flow=%@", flow];
        return [NSString stringWithFormat:@"vless://%@@@%@:%@?%@#%@", uuid ?: @"", server, port, q, name];
    }
    if ([type isEqualToString:@"vmess"]) {
        NSDictionary *vm = @{
            @"v": @"2", @"ps": d[@"tag"] ?: @"rivo", @"add": server, @"port": port,
            @"id": uuid ?: @"", @"aid": d[@"alter_id"] ?: d[@"alterId"] ?: @"0",
            @"net": d[@"transport"] ?: @"tcp", @"type": @"none",
            @"host": sni ?: @"", @"path": @"", @"tls": ([tls[@"enabled"] boolValue] ? @"tls" : @"")
        };
        NSData *j = [NSJSONSerialization dataWithJSONObject:vm options:0 error:nil];
        NSString *b64 = [[j base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
        return [@"vmess://" stringByAppendingString:b64];
    }
    if ([type isEqualToString:@"trojan"]) {
        return [NSString stringWithFormat:@"trojan://%@@%@:%@?security=tls&sni=%@#%@",
                password ?: @"", server, port, sni ?: @"", name];
    }
    if ([type isEqualToString:@"shadowsocks"]) {
        NSData *ui = [[NSString stringWithFormat:@"%@:%@", method, password ?: @""] dataUsingEncoding:NSUTF8StringEncoding];
        NSString *b64 = [[ui base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
        return [NSString stringWithFormat:@"ss://%@@%@:%@#%@", b64, server, port, name];
    }
    return nil;
}

// 从 sing-box 配置 JSON 提取节点
static NSArray *rivoURIsFromConfig(NSString *json) {
    NSMutableArray *uris = [NSMutableArray array];
    NSData *data = [json dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
    if (err || !obj || ![obj isKindOfClass:[NSDictionary class]]) return uris;
    id outbounds = ((NSDictionary *)obj)[@"outbounds"];
    if (![outbounds isKindOfClass:[NSArray class]]) return uris;
    for (id item in (NSArray *)outbounds) {
        if (![item isKindOfClass:[NSDictionary class]]) continue;
        NSString *uri = rivoURIFromSingbox((NSDictionary *)item);
        if (uri && ![uris containsObject:uri]) [uris addObject:uri];
    }
    return uris;
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

static void rivoHandleConfig(NSString *configJson, NSString *source) {
    if (!configJson.length) return;
    NSString *home = NSHomeDirectory();
    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    [configJson writeToFile:[docDir stringByAppendingPathComponent:@"rivo_config.json"]
                 atomically:YES encoding:NSUTF8StringEncoding error:nil];
    rivoAppendLog([NSString stringWithFormat:@"captured config from %@, %lu bytes",
                   source, (unsigned long)[configJson lengthOfBytesUsingEncoding:NSUTF8StringEncoding]]);

    NSArray *uris = rivoURIsFromConfig(configJson);
    if (!uris.count) {
        rivoAppendLog(@"no node uris parsed from config (outbounds missing or unsupported types)");
        return;
    }
    NSString *subText = [uris componentsJoinedByString:@"\n"];
    NSData *subData = [subText dataUsingEncoding:NSUTF8StringEncoding];
    NSString *subB64 = [[subData base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
    NSString *subLink = [@"sub://" stringByAppendingString:subB64];
    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    pb.string = subLink;
    [subText writeToFile:[docDir stringByAppendingPathComponent:@"rivo_sub.txt"]
              atomically:YES encoding:NSUTF8StringEncoding error:nil];
    rivoAppendLog([NSString stringWithFormat:@"parsed %lu nodes, sub copied", (unsigned long)uris.count]);
    rivoShowAlert(@"RivoVPNAD", [NSString stringWithFormat:@"已从明文配置抓到 %lu 个节点，订阅已复制到剪贴板", (unsigned long)uris.count]);
}

#pragma mark - LibboxSetup hook（sing-box gomobile 配置入口）

static IMP origSetupIMP = NULL;

// gomobile 对 func Setup(options *SetupOptions) error 通常导出 +setupWithOptions:error:
static id rivoSetupHook(id self, SEL _cmd, id options, id error) {
    @try {
        NSString *cfg = nil;
        @try { cfg = [options valueForKey:@"baseConfig"]; } @catch (NSException *e) {}
        if (cfg.length) {
            rivoHandleConfig(cfg, @"LibboxSetup.baseConfig");
        } else {
            rivoAppendLog(@"LibboxSetup called but baseConfig empty; options class: %@",
                          NSStringFromClass([options class]));
        }
    } @catch (NSException *e) {
        rivoAppendLog([NSString stringWithFormat:@"setup hook exception: %@", e.reason]);
    }
    if (origSetupIMP) {
        return ((id (*)(id, SEL, id, id))origSetupIMP)(self, _cmd, options, error);
    }
    return nil;
}

static void rivoHookLibboxSetup(void) {
    Class setup = NSClassFromString(@"LibboxSetup");
    if (!setup) {
        rivoAppendLog(@"LibboxSetup class not found");
        return;
    }
    SEL sel = NSSelectorFromString(@"setupWithOptions:error:");
    Method m = class_getClassMethod(setup, sel);
    if (!m) {
        // 备选：无 error 变体
        sel = NSSelectorFromString(@"setupWithOptions:");
        m = class_getClassMethod(setup, sel);
    }
    if (m) {
        origSetupIMP = method_getImplementation(m);
        method_setImplementation(m, (IMP)rivoSetupHook);
        rivoAppendLog(@"LibboxSetup hooked (selector %@)", NSStringFromSelector(sel));
    } else {
        rivoAppendLog(@"LibboxSetup found but no setupWithOptions selector; trying init variants");
        // 实例方法兜底
        SEL sel2 = NSSelectorFromString(@"initWithOptions:error:");
        Method m2 = class_getInstanceMethod(setup, sel2);
        if (!m2) { sel2 = NSSelectorFromString(@"initWithOptions:"); m2 = class_getInstanceMethod(setup, sel2); }
        if (m2) {
            origSetupIMP = method_getImplementation(m2);
            method_setImplementation(m2, (IMP)rivoSetupHook);
            rivoAppendLog(@"LibboxSetup init hooked (selector %@)", NSStringFromSelector(sel2));
        } else {
            rivoAppendLog(@"LibboxSetup no hookable selector found");
        }
    }
}

#pragma mark - 广告 hook（AdMob：加载直接失败）

static void rivoFailFullScreenLoad(id self, SEL _cmd, id adUnitID, id request, id handler) {
    void (^completion)(id, NSError *) = handler;
    if (completion) completion(nil, rivoAdBlockError());
}

static void rivoEmptyBannerLoad(id self, SEL _cmd, id request) {
}

#pragma mark - Unity Ads：load 直接失败（触发 App 免费解锁兜底）

static void rivoUnityLoadFail(id self, SEL _cmd, NSString *placementId, id delegate) {
    SEL failSel = NSSelectorFromString(@"unityAdsLoadFailed:withError:withMessage:");
    if (delegate && [delegate respondsToSelector:failSel]) {
        ((void (*)(id, SEL, id, NSInteger, id))objc_msgSend)(delegate, failSel, placementId, 3, @"No fill (blocked by RivoVPNAD)");
    }
}

#pragma mark - Vungle：load 直接失败

static BOOL rivoVungleLoadFail(id self, SEL _cmd, id placementID, NSError **err) {
    if (err) {
        *err = [NSError errorWithDomain:@"com.vungle" code:3 userInfo:@{NSLocalizedDescriptionKey: @"No fill (blocked)"}];
    }
    return NO;
}

#pragma mark - 展示层兜底拦截

static IMP origAddSubviewIMP = NULL;

static void rivoAddSubview(id self, SEL _cmd, id view) {
    if (rivoIsGADObject(view)) {
        ((UIView *)view).hidden = YES;
    }
    if (origAddSubviewIMP) {
        ((void (*)(id, SEL, id))origAddSubviewIMP)(self, _cmd, view);
    } else {
        struct objc_super sup = { self, [UIView class] };
        ((void (*)(struct objc_super *, SEL, id))objc_msgSendSuper)(&sup, _cmd, view);
    }
}

#pragma mark - 节点抓取（NSURLProtocol 拦 URLSession 全部请求，兜底记录响应）

@interface RivoURLProtocol : NSURLProtocol
@end

@implementation RivoURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"RivoAlreadyFetched" inRequest:request]) return NO;
    return rivoIsTargetURL(request.URL.absoluteString);
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSMutableURLRequest *newReq = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"RivoAlreadyFetched" inRequest:newReq];

    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:newReq completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (data.length) {
            rivoAppendLog([NSString stringWithFormat:@"response %lu bytes from %@",
                           (unsigned long)data.length, self.request.URL.absoluteString]);
            // 若响应本身就是明文配置 JSON，直接尝试解析；否则原样落盘
            NSError *jerr = nil;
            id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jerr];
            if (!jerr && obj && [obj isKindOfClass:[NSDictionary class]]) {
                NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                NSArray *uris = rivoURIsFromConfig(json);
                if (uris.count) {
                    rivoHandleConfig(json, @"http response");
                } else {
                    NSString *home = NSHomeDirectory();
                    NSString *rawPath = [home stringByAppendingPathComponent:@"Documents/rivo_nodes_raw.json"];
                    [data writeToFile:rawPath atomically:YES];
                }
            } else {
                NSString *home = NSHomeDirectory();
                NSString *rawPath = [home stringByAppendingPathComponent:@"Documents/rivo_nodes_raw.json"];
                [data writeToFile:rawPath atomically:YES];
            }
        }
        if (err) {
            [self.client URLProtocol:self didFailWithError:err];
        } else {
            [self.client URLProtocol:self didReceiveResponse:resp cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:data ?: [NSData data]];
            [self.client URLProtocolDidFinishLoading:self];
        }
    }];
    [task resume];
}

- (void)stopLoading {
}

@end

#pragma mark - 备用：NSURLSession dataTask hook

static IMP origDataTaskIMP = NULL;

static id rivoDataTask(id self, SEL _cmd, NSURLRequest *req, id completion) {
    NSString *u = req.URL.absoluteString;
    if (rivoIsTargetURL(u)) {
        void (^origComp)(NSData *, NSURLResponse *, NSError *) = completion;
        void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
            if (origComp) origComp(data, resp, err);
            if (data.length) {
                NSString *home = NSHomeDirectory();
                NSString *rawPath = [home stringByAppendingPathComponent:@"Documents/rivo_nodes_raw.json"];
                [data writeToFile:rawPath atomically:YES];
                rivoAppendLog([NSString stringWithFormat:@"dataTask response %lu bytes from %@",
                               (unsigned long)data.length, u]);
            }
        };
        return ((id (*)(id, SEL, id, id))origDataTaskIMP)(self, _cmd, req, wrapped);
    }
    return ((id (*)(id, SEL, id, id))origDataTaskIMP)(self, _cmd, req, completion);
}

#pragma mark - 执行 hook（延迟轮询等所有类加载）

static void rivoDoHook(void) {
    static BOOL hooked = NO;
    if (hooked) return;
    hooked = YES;

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

    // 2) Unity Ads：load 直接失败
    Class unityAds = NSClassFromString(@"UnityAds");
    if (unityAds) {
        Method mu = class_getClassMethod(unityAds, @selector(load:loadDelegate:));
        if (mu) method_setImplementation(mu, (IMP)rivoUnityLoadFail);
    }

    // 3) Vungle：load 直接失败
    Class vungleAds = NSClassFromString(@"VungleAds");
    if (vungleAds) {
        Method mv = class_getClassMethod(vungleAds, NSSelectorFromString(@"loadPlacementWithPlacementID:error:"));
        if (mv) method_setImplementation(mv, (IMP)rivoVungleLoadFail);
    }

    // 4) 展示层兜底：GAD/Unity 视图挂载即隐藏
    Method ma = class_getInstanceMethod([UIView class], @selector(addSubview:));
    if (ma) {
        origAddSubviewIMP = method_getImplementation(ma);
        method_setImplementation(ma, (IMP)rivoAddSubview);
    }

    // 5) 节点抓取主方案：注册 NSURLProtocol
    [NSURLProtocol registerClass:[RivoURLProtocol class]];

    // 6) 备用：NSURLSession dataTask hook
    Method md = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
    if (md) {
        origDataTaskIMP = method_getImplementation(md);
        method_setImplementation(md, (IMP)rivoDataTask);
    }

    // 7) v6 新增：LibboxSetup 明文配置抓取
    rivoHookLibboxSetup();
}

static void rivoTryHook(int attempt) {
    Class gRew = NSClassFromString(@"GADRewardedAd");
    Class unityAds = NSClassFromString(@"UnityAds");
    Class setup = NSClassFromString(@"LibboxSetup");
    if ((gRew || unityAds || setup) && attempt >= 2) {
        rivoDoHook();
        return;
    }
    if (attempt >= 20) {
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
