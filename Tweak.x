#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <CommonCrypto/CommonCryptor.h>
#import <dlfcn.h>
#include "fishhook.h"

// ===== RivoVPNAD v6.2: fishhook CCCrypt 解密抓取 + 广告hook保留 + 响应按URL分存 =====
// v6 发现 LibboxSetup 是 C 函数非 ObjC 类；config 接口(/api/v1/ios/config)返回的是
// rivoLinks 密文(AES)。v6.2 改用 fishhook 重绑定 CommonCrypto 的 CCCrypt，
// 拦截 kCCDecrypt 输出(即解密后的明文节点数据)，落盘验证 + 尝试解析成订阅。

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

// sing-box / 通用节点字典 -> Shadowrocket URI
static NSString *rivoURIFromDict(NSDictionary *d) {
    NSString *type = d[@"type"] ?: d[@"protocol"];
    if ([type isKindOfClass:[NSString class]]) {
        if ([type isEqualToString:@"selector"] || [type isEqualToString:@"urltest"] ||
            [type isEqualToString:@"direct"] || [type isEqualToString:@"block"] ||
            [type isEqualToString:@"dns"] || [type isEqualToString:@"reject"] ||
            [type isEqualToString:@"loopback"] || [type isEqualToString:@"wireguard"] ||
            [type isEqualToString:@"hysteria2"] || [type isEqualToString:@"tuic"] ||
            [type isEqualToString:@"http"] || [type isEqualToString:@"socks"] ||
            [type isEqualToString:@"shadowtls"]) {
            return nil;
        }
    }
    NSString *server = d[@"server"] ?: d[@"host"] ?: d[@"address"] ?: d[@"addr"] ?: d[@"ip"];
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
    NSString *name = rivoTagName(d[@"tag"] ?: d[@"name"] ?: d[@"remark"] ?: @"rivo");
    NSDictionary *tls = d[@"tls"];
    NSString *sni = d[@"sni"] ?: d[@"servername"] ?: d[@"serverName"];
    if ([tls isKindOfClass:[NSDictionary class]] && !sni) sni = tls[@"server_name"] ?: tls[@"serverName"];
    NSString *uuid = d[@"uuid"] ?: d[@"id"];
    NSString *password = d[@"password"] ?: d[@"key"];
    NSString *method = d[@"method"] ?: d[@"cipher"] ?: @"aes-128-gcm";

    if ([type isKindOfClass:[NSString class]] && [type isEqualToString:@"vless"]) {
        NSString *flow = d[@"flow"];
        NSString *q = [NSString stringWithFormat:@"encryption=none&security=tls&sni=%@&fp=chrome&type=tcp",
                       sni ?: @""];
        if (flow.length) q = [q stringByAppendingFormat:@"&flow=%@", flow];
        return [NSString stringWithFormat:@"vless://%@@@%@:%@?%@#%@", uuid ?: @"", server, port, q, name];
    }
    if ([type isKindOfClass:[NSString class]] && [type isEqualToString:@"vmess"]) {
        NSDictionary *vm = @{
            @"v": @"2", @"ps": d[@"tag"] ?: d[@"name"] ?: @"rivo", @"add": server, @"port": port,
            @"id": uuid ?: @"", @"aid": d[@"alter_id"] ?: d[@"alterId"] ?: @"0",
            @"net": d[@"transport"] ?: @"tcp", @"type": @"none",
            @"host": sni ?: @"", @"path": @"", @"tls": ([tls[@"enabled"] boolValue] ? @"tls" : @"")
        };
        NSData *j = [NSJSONSerialization dataWithJSONObject:vm options:0 error:nil];
        NSString *b64 = [[j base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
        return [@"vmess://" stringByAppendingString:b64];
    }
    if (uuid && password && [password length] > 0) {
        return [@"trojan://" stringByAppendingString:[NSString stringWithFormat:@"%@:%@@%@:%@?peer=%@#%@",
                                                      uuid, password, server, port, sni ?: @"", name]];
    }
    if (uuid) {
        return [@"vless://" stringByAppendingString:[NSString stringWithFormat:@"%@:%@@%@:%@?encryption=none&security=tls&sni=%@#%@",
                                                     uuid, @"", server, port, sni ?: @"", name]];
    }
    if (password && method) {
        NSData *ui = [[NSString stringWithFormat:@"%@:%@", method, password] dataUsingEncoding:NSUTF8StringEncoding];
        NSString *b64 = [[ui base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
        return [NSString stringWithFormat:@"ss://%@@%@:%@#%@", b64, server, port, name];
    }
    return nil;
}

// 递归收集节点（支持任意嵌套结构）
static void rivoCollectNodes(id obj, NSMutableArray *uris, int depth) {
    if (!obj || depth > 7) return;
    if ([obj isKindOfClass:[NSArray class]]) {
        for (id item in (NSArray *)obj) {
            rivoCollectNodes(item, uris, depth + 1);
        }
    } else if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *d = (NSDictionary *)obj;
        NSString *uri = rivoURIFromDict(d);
        if (uri && ![uris containsObject:uri]) [uris addObject:uri];
        for (NSString *key in d.allKeys) {
            id val = d[key];
            if ([val isKindOfClass:[NSArray class]] || [val isKindOfClass:[NSDictionary class]]) {
                rivoCollectNodes(val, uris, depth + 1);
            }
        }
    }
}

static NSArray *rivoURIsFromString(NSString *json) {
    NSMutableArray *uris = [NSMutableArray array];
    NSData *data = [json dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
    if (err || !obj) return uris;
    rivoCollectNodes(obj, uris, 0);
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
    rivoAppendLog(@"captured config from %@, %lu bytes",
                  source, (unsigned long)[configJson lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);

    NSArray *uris = rivoURIsFromString(configJson);
    if (!uris.count) {
        rivoAppendLog(@"no node uris parsed from %@ (len=%lu)", source,
                      (unsigned long)[configJson lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
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
    rivoAppendLog(@"parsed %lu nodes from %@, sub copied", (unsigned long)uris.count, source);
    rivoShowAlert(@"RivoVPNAD", [NSString stringWithFormat:@"已从%@抓到 %lu 个节点，订阅已复制到剪贴板",
                                 source, (unsigned long)uris.count]);
}

#pragma mark - CCCrypt hook（fishhook 重绑定 CommonCrypto）

static CCCryptorStatus (*orig_CCCrypt)(CCOperation op, CCAlgorithm alg, CCOptions options,
                                       const void *key, size_t keyLength, const void *iv,
                                       const void *dataIn, size_t dataInLength,
                                       void *dataOut, size_t dataOutAvailable,
                                       size_t *dataOutMoved);

static CCCryptorStatus rivo_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options,
                                    const void *key, size_t keyLength, const void *iv,
                                    const void *dataIn, size_t dataInLength,
                                    void *dataOut, size_t dataOutAvailable,
                                    size_t *dataOutMoved) {
    CCCryptorStatus st = kCCDecrypt; // 若 orig 未就绪，直接返回失败避免崩溃
    if (orig_CCCrypt) {
        st = orig_CCCrypt(op, alg, options, key, keyLength, iv,
                          dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved);
    } else {
        // orig 未设置：调用系统真函数
        CCCryptorStatus (*sys)(CCOperation, CCAlgorithm, CCOptions, const void *, size_t,
                               const void *, const void *, size_t, void *, size_t, size_t *) = dlsym(RTLD_DEFAULT, "CCCrypt");
        if (sys) st = sys(op, alg, options, key, keyLength, iv,
                          dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved);
        else return kCCUnimplemented;
    }

    @try {
        if (st == kCCSuccess && op == kCCDecrypt && dataOut && dataOutMoved && *dataOutMoved > 0) {
            size_t n = *dataOutMoved;
            NSString *str = nil;
            @try {
                str = [[NSString alloc] initWithBytes:dataOut length:n encoding:NSUTF8StringEncoding];
            } @catch (NSException *e) {}

            // 样本落盘（限制长度），确认明文结构
            static int rivoDumpCount = 0;
            if (str.length > 20) {
                rivoDumpCount++;
                NSString *home = NSHomeDirectory();
                NSString *dumpPath = [home stringByAppendingPathComponent:@"Documents/rivo_decrypt_dump.log"];
                NSString *sample = str.length > 600 ? [str substringToIndex:600] : str;
                NSString *entry = [NSString stringWithFormat:@"--- dump#%d alg=%d keyLen=%zu inLen=%zu outLen=%zu ---\n%@\n",
                                   rivoDumpCount, (int)alg, keyLength, dataInLength, n, sample];
                NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:dumpPath];
                if (!fh) {
                    [entry writeToFile:dumpPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
                } else {
                    [fh seekToEndOfFile];
                    [fh writeData:[entry dataUsingEncoding:NSUTF8StringEncoding]];
                    [fh closeFile];
                }

                // 若明文含节点特征（server/outbounds/uuid/address+port），尝试解析
                NSString *lower = [str lowercaseString];
                if ([lower containsString:@"\"server\""] ||
                    [lower containsString:@"outbounds"] ||
                    ([lower containsString:@"uuid"] && [lower containsString:@"port"]) ||
                    ([lower containsString:@"address"] && [lower containsString:@"port"])) {
                    rivoHandleConfig(str, @"CCCrypt decrypt");
                } else if (rivoDumpCount <= 30) {
                    rivoAppendLog(@"CCCrypt decrypt len=%zu sample=%@", n,
                                  sample.length > 120 ? [sample substringToIndex:120] : sample);
                }
            }
        }
    } @catch (NSException *e) {
        rivoAppendLog(@"CCCrypt hook exception: %@", e.reason);
    }
    return st;
}

static void rivoHookCCCrypt(void) {
    int rc = rebind_symbols((struct rebinding[]){
        {"CCCrypt", (void *)rivo_CCCrypt, (void **)&orig_CCCrypt}
    }, 1);
    rivoAppendLog(@"fishhook CCCrypt rebind rc=%d", rc);
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

#pragma mark - 节点抓取（NSURLProtocol + dataTask，响应按 URL 分存，二进制不覆盖文本）

@interface RivoURLProtocol : NSURLProtocol
@end

static NSString *rivoSaveResponse(NSData *data, NSString *url, NSString *dir) {
    // 按 URL 生成安全文件名，避免互相覆盖
    NSString *name = [[url lastPathComponent] stringByReplacingOccurrencesOfString:@"." withString:@"_"];
    if (name.length < 3) name = @"resp";
    NSString *path = [dir stringByAppendingPathComponent:[NSString stringWithFormat:@"rivo_http_%@.bin", name]];
    [data writeToFile:path atomically:YES];
    // 同时保存原始 JSON 响应到固定名（若可解码为 UTF-8）
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (str.length) {
        NSString *jsonPath = [dir stringByAppendingPathComponent:@"rivo_config_http.json"];
        [str writeToFile:jsonPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        // 若含节点特征就解析
        NSString *lower = [str lowercaseString];
        if ([lower containsString:@"rivoLinks"] || [lower containsString:@"\"server\""] ||
            [lower containsString:@"outbounds"]) {
            rivoAppendLog(@"http resp %lu bytes from %@ (json-like)", (unsigned long)data.length, url);
            if (![lower containsString:@"rivoLinks"]) {
                rivoHandleConfig(str, @"http config");
            }
        } else {
            rivoAppendLog(@"http resp %lu bytes from %@ (utf8)", (unsigned long)data.length, url);
        }
    } else {
        rivoAppendLog(@"http resp %lu bytes from %@ (binary)", (unsigned long)data.length, url);
    }
    return path;
}

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
            NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
            rivoSaveResponse(data, self.request.URL.absoluteString, dir);
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

static IMP origDataTaskIMP = NULL;

static id rivoDataTask(id self, SEL _cmd, NSURLRequest *req, id completion) {
    NSString *u = req.URL.absoluteString;
    if (rivoIsTargetURL(u)) {
        void (^origComp)(NSData *, NSURLResponse *, NSError *) = completion;
        void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
            if (origComp) origComp(data, resp, err);
            if (data.length) {
                NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
                rivoSaveResponse(data, u, dir);
            }
        };
        return ((id (*)(id, SEL, id, id))origDataTaskIMP)(self, _cmd, req, wrapped);
    }
    return ((id (*)(id, SEL, id, id))origDataTaskIMP)(self, _cmd, req, completion);
}

#pragma mark - NSJSONSerialization hook（明文节点 JSON 必经之路）

static BOOL rivoLooksLikeConfigString(NSString *s) {
    if (s.length < 120) return NO;
    NSString *low = [s lowercaseString];
    return [low containsString:@"\"server\""] ||
           [low containsString:@"outbounds"] ||
           ([low containsString:@"uuid"] && [low containsString:@"server_port"]) ||
           ([low containsString:@"rivo"] && [low containsString:@"server"]);
}

static NSData *(*orig_NSJSON_dataWithJSONObject)(Class, SEL, id, NSJSONWritingOptions, NSError **);

static NSData *rivo_NSJSON_dataWithJSONObject(Class cls, SEL _cmd, id obj, NSJSONWritingOptions opt, NSError **err) {
    NSData *data = orig_NSJSON_dataWithJSONObject(cls, _cmd, obj, opt, err);
    @try {
        if (data.length > 120) {
            NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (rivoLooksLikeConfigString(s)) {
                rivoAppendLog(@"NSJSONSerialization serialize captured (%lu bytes)", (unsigned long)data.length);
                rivoHandleConfig(s, @"NSJSONSerialization serialize");
            }
        }
    } @catch (NSException *e) {}
    return data;
}

static id (*orig_NSJSON_JSONObjectWithData)(Class, SEL, NSData *, NSJSONReadingOptions, NSError **);

static id rivo_NSJSON_JSONObjectWithData(Class cls, SEL _cmd, NSData *data, NSJSONReadingOptions opt, NSError **err) {
    @try {
        if (data.length > 120) {
            NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (rivoLooksLikeConfigString(s)) {
                rivoAppendLog(@"NSJSONSerialization parse captured (%lu bytes)", (unsigned long)data.length);
                rivoHandleConfig(s, @"NSJSONSerialization parse");
            }
        }
    } @catch (NSException *e) {}
    return orig_NSJSON_JSONObjectWithData(cls, _cmd, data, opt, err);
}

static void rivoHookNSJSON(void) {
    Method m1 = class_getClassMethod([NSJSONSerialization class], @selector(dataWithJSONObject:options:error:));
    if (m1) {
        orig_NSJSON_dataWithJSONObject = (void *)method_getImplementation(m1);
        method_setImplementation(m1, (IMP)rivo_NSJSON_dataWithJSONObject);
    }
    Method m2 = class_getClassMethod([NSJSONSerialization class], @selector(JSONObjectWithData:options:error:));
    if (m2) {
        orig_NSJSON_JSONObjectWithData = (void *)method_getImplementation(m2);
        method_setImplementation(m2, (IMP)rivo_NSJSON_JSONObjectWithData);
    }
    rivoAppendLog(@"NSJSONSerialization hooks installed");
}

#pragma mark - 执行 hook

static void rivoDoHook(void) {
    static BOOL hooked = NO;
    if (hooked) return;
    hooked = YES;

    // 0) CCCrypt + NSJSONSerialization 已在 constructor 中 hook（勿重复，会递归）

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

    // 5) 节点抓取：注册 NSURLProtocol
    [NSURLProtocol registerClass:[RivoURLProtocol class]];

    // 6) 备用：NSURLSession dataTask hook
    Method md = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
    if (md) {
        origDataTaskIMP = method_getImplementation(md);
        method_setImplementation(md, (IMP)rivoDataTask);
    }
}

static void rivoTryHook(int attempt) {
    Class gRew = NSClassFromString(@"GADRewardedAd");
    Class unityAds = NSClassFromString(@"UnityAds");
    if ((gRew || unityAds) && attempt >= 2) {
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
    // CCCrypt + NSJSONSerialization hook 不需要等类加载，constructor 里立刻做
    rivoHookCCCrypt();
    rivoHookNSJSON();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
                       rivoTryHook(0);
                   });
}
