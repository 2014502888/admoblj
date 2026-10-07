#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <CommonCrypto/CommonCryptor.h>
#import <dlfcn.h>
#import <string.h>
#import <mach/mach.h>
#include "fishhook.h"

// v7.3: iPhoneOS 26.5 新 SDK 中 <mach/mach_vm.h> 整文件 #error "unsupported"，
// 删除该 import，mach_vm_read 改为 dlsym 动态查找（符号存在才调用，编译零依赖，
// 运行时找不到符号则优雅跳过字符串扫描，不影响广告拦截）。
typedef kern_return_t (*rivo_mach_vm_read_t)(vm_map_t, mach_vm_address_t, mach_vm_size_t,
                                             vm_offset_t *, mach_msg_type_number_t *);
static kern_return_t rivoMachVmRead(vm_map_t task, mach_vm_address_t addr, mach_vm_size_t size,
                                    vm_offset_t *data, mach_msg_type_number_t *cnt) {
    static rivo_mach_vm_read_t fn = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fn = (rivo_mach_vm_read_t)dlsym(RTLD_DEFAULT, "mach_vm_read");
    });
    if (!fn) return KERN_FAILURE;
    return fn(task, addr, size, data, cnt);
}

// ===== RivoVPNAD v7: 广告展示层拦截（激励广告跳过展示直接发奖励）+ 节点抓取 =====
// v7 变更：
//   - 定位到"点连接后全屏广告+进度条"= 激励广告（AdMob Rewarded / UnityAds show）在展示层弹出，
//     旧版只拦 load（加载失败）但 App 仍能展示，addSubview 兜底也拦不到全屏 modal。
//   - 激励广告（GADRewardedAd / UnityAds）：不拦 load（App 需加载成功才进发奖流程），
//     改为 hook 展示层 present/show —— 跳过广告画面，直接回调"已看完"→ PRO 免费时长照拿。
//   - 开屏/插屏/横幅（GADAppOpenAd / GADInterstitialAd / GADBannerView）：load 直接失败，零广告请求。
//   - 万能兜底：hook UIViewController presentViewController，任何广告类 VC 弹全屏直接拦截。
//   - 全部拦截点写 rivo_debug.log，方便回传确认真实展示源。
//   - 节点抓取保留：CCCrypt/CCCryptor/LibboxSetup/NSJSON + NSURLProtocol/dataTask 按 URL 分存。
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

// 节点/重入全局标志（必须在 rivoHandleConfig 之前声明）
static int rivoJSONReentry = 0;        // NSJSONSerialization hook 重入保护
static BOOL rivoConfigHandled = NO;    // 同会话成功解析过节点则不再重复弹窗
static size_t rivoLastLen = 0;         // 去重：上次处理的内容大小
static unsigned char rivoLastHead[48]; // 去重：上次处理内容头部

// 同一内容只处理一次（App 会循环解析同一个 config，避免 1700+ 次写文件拖慢）
static BOOL rivoIsDuplicate(NSData *data) {
    size_t n = data.length;
    const unsigned char *b = (const unsigned char *)data.bytes;
    size_t cmp = n < 48 ? n : 48;
    if (n == rivoLastLen && memcmp(b, rivoLastHead, cmp) == 0) {
        return YES;
    }
    rivoLastLen = n;
    memset(rivoLastHead, 0, sizeof(rivoLastHead));
    if (cmp > 0) memcpy(rivoLastHead, b, cmp);
    return NO;
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
    if (rivoConfigHandled) return;   // 同会话成功过一次就不再重复弹窗
    rivoConfigHandled = YES;
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

#pragma mark - v7 展示层拦截（激励广告跳过展示直接发奖励，其余不展示）

// 构造一个最小可用的 GADAdReward（amount=1, type=reward）
static id rivoMakeReward(void) {
    @try {
        Class cls = NSClassFromString(@"GADAdReward");
        if (!cls) return nil;
        id obj = [cls alloc];
        SEL sel = NSSelectorFromString(@"initWithRewardType:amount:");
        if ([obj respondsToSelector:sel]) {
            return ((id (*)(id, SEL, id, id))objc_msgSend)(obj, sel, @"reward",
                                                           [NSDecimalNumber decimalNumberWithString:@"1"]);
        }
        SEL plain = NSSelectorFromString(@"init");
        if ([obj respondsToSelector:plain]) {
            return ((id (*)(id, SEL))objc_msgSend)(obj, plain);
        }
        return obj;
    } @catch (NSException *e) {
        rivoAppendLog(@"AD-BLOCK: rivoMakeReward 异常 %@", e);
        return nil;
    }
}

// v7.4: 模拟完整广告生命周期（解决 PRO 转圈）
// 真实 GADRewardedAd 展示时序：present → adWillPresentFullScreenContent → (播放)
// → rewardHandler(reward) → adDidDismissFullScreenContent。
// App 可能在 dismissed 后才发奖/续时长；旧代码只 KVC delegate 且不通知 willPresent/dismiss，
// 新版 SDK delegate 属性是 fullScreenContentDelegate，KVC 拿不到 → 永远等 → PRO 转圈。
// 现在：多属性名取 delegate + 完整回调序列（willPresent/impression 立即、dismiss 延迟 0.6s）。

// 取全屏广告 delegate（兼容新旧属性名）
static id rivoAdDelegate(id ad) {
    @try {
        for (NSString *key in @[@"fullScreenContentDelegate", @"delegate", @"adDelegate", @"interstitialDelegate", @"rewardedAdDelegate"]) {
            id v = [ad valueForKey:key];
            if (v) return v;
        }
    } @catch (NSException *e) {
        rivoAppendLog(@"AD-BLOCK: rivoAdDelegate 异常 %@", e);
    }
    return nil;
}

// 通知 delegate 广告生命周期（模拟完整展示）
static void rivoSimulateLifecycle(id ad, BOOL withReward) {
    id delegate = rivoAdDelegate(ad);
    if (!delegate) {
        rivoAppendLog(@"AD-BLOCK: 未找到广告 delegate，模拟回调失败 (class=%@)", NSStringFromClass([ad class]));
        return;
    }
    @try {
        SEL willSel = NSSelectorFromString(@"adWillPresentFullScreenContent:");
        if ([delegate respondsToSelector:willSel]) {
            ((void (*)(id, SEL, id))objc_msgSend)(delegate, willSel, ad);
        }
        SEL impSel = NSSelectorFromString(@"adDidRecordImpression:");
        if ([delegate respondsToSelector:impSel]) {
            ((void (*)(id, SEL, id))objc_msgSend)(delegate, impSel, ad);
        }
        SEL dismissSel = NSSelectorFromString(@"adDidDismissFullScreenContent:");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @try {
                if ([delegate respondsToSelector:dismissSel]) {
                    ((void (*)(id, SEL, id))objc_msgSend)(delegate, dismissSel, ad);
                }
                // 兼容非标准名 dismiss 回调
                SEL d2 = NSSelectorFromString(@"adDidDismiss:");
                if ([delegate respondsToSelector:d2]) {
                    ((void (*)(id, SEL, id))objc_msgSend)(delegate, d2, ad);
                }
            } @catch (NSException *e) {
                rivoAppendLog(@"AD-BLOCK: dismiss 回调异常 %@", e);
            }
        });
    } @catch (NSException *e) {
        rivoAppendLog(@"AD-BLOCK: lifecycle 异常 %@", e);
    }
}

// GADRewardedAd / GADRewardedInterstitialAd present：不展示，立即发奖励 + 模拟完整生命周期
static void rivoRewardPresent(id self, SEL _cmd, id vc, id rewardHandler) {
    rivoAppendLog(@"AD-BLOCK: %@ present 拦截 -> 直接发奖励 (class=%@)", NSStringFromSelector(_cmd), NSStringFromClass([self class]));
    if (rewardHandler) {
        @try {
            ((void (^)(id))rewardHandler)(rivoMakeReward());
        } @catch (NSException *e) {
            rivoAppendLog(@"AD-BLOCK: rewardHandler 异常 %@", e);
        }
    }
    rivoSimulateLifecycle(self, YES);
}

// GADInterstitialAd / GADAppOpenAd present：不展示（load 已失败，一般不会到这一步）
static void rivoFullScreenPresent(id self, SEL _cmd, id vc) {
    rivoAppendLog(@"AD-BLOCK: %@ present 拦截 -> 不展示", NSStringFromClass([self class]));
    rivoSimulateLifecycle(self, NO);
}

// UnityAds show：不展示，直接走"完成"回调（UnityAdsShowFinishState=0 COMPLETED）
static void rivoUnityShow(id self, SEL _cmd, NSString *placementId, id showDelegate) {
    rivoAppendLog(@"AD-BLOCK: UnityAds show 拦截 -> 直接完成 (placement=%@)", placementId);
    @try {
        SEL startSel = NSSelectorFromString(@"unityAdsShowStart:");
        if (showDelegate && [showDelegate respondsToSelector:startSel]) {
            ((void (*)(id, SEL, id))objc_msgSend)(showDelegate, startSel, placementId);
        }
        SEL completeSel = NSSelectorFromString(@"unityAdsShowComplete:withFinishState:");
        if (showDelegate && [showDelegate respondsToSelector:completeSel]) {
            ((void (*)(id, SEL, id, NSInteger))objc_msgSend)(showDelegate, completeSel, placementId, 0);
        }
    } @catch (NSException *e) {
        rivoAppendLog(@"AD-BLOCK: rivoUnityShow 异常 %@", e);
    }
}

// 万能兜底：任何广告 VC 通过 presentViewController 弹全屏时直接拦截
static IMP origPresentIMP = NULL;

// v7.7: 前置声明（备用函数，GAD 已改放行+秒关方案）
static id rivoFindRewardedAdInObject(id obj);
static void rivoTryRewardFromAd(id ad);

// v7.7: GAD 全屏广告出现后 0.4 秒自动关闭（触发 App 自身 dismiss 回调自然发奖，不手动调未知 block）
static IMP origGADVCViewDidAppearIMP = NULL;

static void rivoGADVCViewDidAppear(id self, SEL _cmd, BOOL animated) {
    if (origGADVCViewDidAppearIMP) {
        ((void (*)(id, SEL, BOOL))origGADVCViewDidAppearIMP)(self, _cmd, animated);
    }
    rivoAppendLog(@"AD-BLOCK: GAD 广告已显示，0.4s 后自动关闭（模拟看完）");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        @try {
            UIViewController *vc = self;
            UIViewController *p = vc.presentingViewController;
            if (p) {
                [p dismissViewControllerAnimated:NO completion:nil];
            } else {
                [vc dismissViewControllerAnimated:NO completion:nil];
            }
            rivoAppendLog(@"AD-BLOCK: GAD 广告已 dismiss");
        } @catch (NSException *e) {
            rivoAppendLog(@"AD-BLOCK: dismiss 异常 %@", e);
        }
    });
}

// v7.6.1: 遍历对象 ivar 找 GADRewarded* 广告对象（带深度限制 + 防环，避免对象图循环引用导致栈溢出闪退）
static NSMutableSet *rivoVisitedObjects(void) {
    static NSMutableSet *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [NSMutableSet set]; });
    return s;
}

static id rivoFindRewardedAdInObjectDepth(id obj, int depth) {
    if (!obj || depth > 3) return nil; // 最多 3 层，防无限递归
    NSMutableSet *visited = rivoVisitedObjects();
    if ([visited containsObject:obj]) return nil; // 防环
    [visited addObject:obj];
    @autoreleasepool {
        Class cls = [obj class];
        NSString *clsName = NSStringFromClass(cls);
        if ([clsName containsString:@"Rewarded"]) return obj; // 对象本身就是激励广告
        unsigned int count = 0;
        Ivar *ivars = class_copyIvarList(cls, &count);
        id found = nil;
        for (unsigned int i = 0; i < count && !found; i++) {
            Ivar iv = ivars[i];
            @try {
                const char *t = ivar_getTypeEncoding(iv);
                if (!t || t[0] != '@') continue; // v7.10: 只读对象类型 ivar，C 类型跳过防崩
                id val = object_getIvar(obj, iv);
                if (!val) continue;
                NSString *vcls = NSStringFromClass([val class]);
                // 值类名含 Rewarded 的 ivar 就是激励广告对象（可能嵌一层：全屏 VC -> 广告）
                if ([vcls containsString:@"Rewarded"] || [vcls containsString:@"GADFullScreenAd"]) {
                    found = val;
                    break;
                }
            } @catch (NSException *e) {}
        }
        if (!found) {
            // 递归：某些对象是包装器，广告在它的 ivar 里
            for (unsigned int i = 0; i < count; i++) {
                Ivar iv = ivars[i];
                @try {
                    const char *t = ivar_getTypeEncoding(iv);
                    if (!t || t[0] != '@') continue; // v7.10: 同上
                    id val = object_getIvar(obj, iv);
                    if (val) {
                        id inner = rivoFindRewardedAdInObjectDepth(val, depth + 1);
                        if (inner) { found = inner; break; }
                    }
                } @catch (NSException *e) {}
            }
        }
        free(ivars);
        return found;
    }
}

// v7.7: 以下函数已不再被调用（GAD 改放行+秒关方案），保留备用，加 unused 防 -Werror
static id rivoFindRewardedAdInObject(id obj) __attribute__((unused));
static void rivoTryRewardFromAd(id ad) __attribute__((unused));

static id rivoFindRewardedAdInObject(id obj) {
    [rivoVisitedObjects() removeAllObjects]; // 每次调用清空 visited
    return rivoFindRewardedAdInObjectDepth(obj, 0);
}

// v7.6.1: block 类型校验（block 对象的 isa 链含 NSBlock，非 block 调用会崩）
static BOOL rivoIsBlock(id obj) {
    if (!obj) return NO;
    Class blockClass = objc_getClass("NSBlock");
    if (!blockClass) return NO;
    Class cls = object_getClass(obj);
    while (cls) {
        if (cls == blockClass) return YES;
        cls = class_getSuperclass(cls);
    }
    return NO;
}

// v7.10: block 签名验证——手动调未知签名 block 是 v7.6/v7.9 闪退根源（EXC_BAD_ACCESS，
// @try 抓不住）。v7.10 读 block 描述符签名，仅当形如 v@?@（block 自身 + 单个 id 参数）
// 才调用；否则跳过，走 delegate 生命周期回调（签名已知，安全）。
#define RIVO_BLOCK_HAS_COPY_DISPOSE (1 << 25)
#define RIVO_BLOCK_HAS_SIGNATURE    (1 << 30)

struct rivoBlockLiteral {
    void *isa;
    int flags;
    int reserved;
    void *invoke;
    void *descriptor;
};

static NSString *rivoBlockSignature(id block) {
    if (!block) return nil;
    struct rivoBlockLiteral *lit = (__bridge struct rivoBlockLiteral *)block;
    if (!lit) return nil;
    int flags = lit->flags;
    if (!(flags & RIVO_BLOCK_HAS_SIGNATURE)) return nil;
    void *p = (char *)lit->descriptor + 16; // 跳过 descriptor_1(reserved+size)
    if (flags & RIVO_BLOCK_HAS_COPY_DISPOSE) p = (char *)p + 16; // 跳过 copy/dispose
    const char *sig = *(const char **)p;
    if (!sig) return nil;
    return [NSString stringWithUTF8String:sig];
}

static BOOL rivoBlockIsRewardHandler(NSString *sig) {
    if (!sig.length) return NO;
    // 去掉偏移数字，压缩为紧凑编码（v@?@ / v@?@@ / v@?）
    NSMutableString *m = [NSMutableString string];
    for (NSUInteger i = 0; i < sig.length; i++) {
        unichar c = [sig characterAtIndex:i];
        if (c >= '0' && c <= '9') continue;
        [m appendFormat:@"%C", c];
    }
    NSArray *parts = [m componentsSeparatedByString:@"@?"];
    if (parts.count != 2) return NO;
    return [parts[1] isEqualToString:@"@"];
}

// v7.9: 从广告对象安全触发奖励（KVC 精确属性名 + 签名验证 + 生命周期兜底）
static void rivoTriggerRewardSafe(id ad) {
    @try {
        if (!ad) return;
        NSArray *handlerKeys = @[@"userDidEarnRewardHandler", @"didEarnRewardHandler",
                                 @"rewardHandler", @"earnedRewardHandler"];
        for (NSString *k in handlerKeys) {
            id h = nil;
            @try { h = [ad valueForKey:k]; } @catch (NSException *e) {}
            if (h && rivoIsBlock(h)) {
                NSString *sig = rivoBlockSignature(h);
                if (sig.length && rivoBlockIsRewardHandler(sig)) {
                    @try {
                        ((void (^)(id))h)(rivoMakeReward());
                        rivoAppendLog(@"AD-BLOCK: ★已触发奖励 handler (key=%@ sig=%@ ad=%@)", k, sig, NSStringFromClass([ad class]));
                        return;
                    } @catch (NSException *e) {
                        rivoAppendLog(@"AD-BLOCK: reward handler 调用异常 %@", e);
                    }
                } else {
                    rivoAppendLog(@"AD-BLOCK: reward block 签名不符跳过 (key=%@ sig=%@)", k, sig ?: @"(nil)");
                }
            }
        }
        // 拿不到/不能安全调用 block → 模拟完整生命周期（willPresent → impression → 0.6s dismiss 回调）
        rivoAppendLog(@"AD-BLOCK: 未安全触发 reward handler，模拟生命周期 (ad=%@)", NSStringFromClass([ad class]));
        rivoSimulateLifecycle(ad, YES);
    } @catch (NSException *e) {
        rivoAppendLog(@"AD-BLOCK: rivoTriggerRewardSafe 异常 %@", e);
    }
}

static UIViewController *rivoTopPresentedVC(void) {
    UIWindow *w = nil;
    for (UIWindow *ww in [UIApplication sharedApplication].windows) {
        if (ww.rootViewController) { w = ww; break; }
    }
    if (!w) return nil;
    UIViewController *top = w.rootViewController;
    while (top.presentedViewController) top = top.presentedViewController;
    return top;
}

static void rivoPresent(id self, SEL _cmd, id vc, BOOL animated, id completion) {
    @try {
        NSString *cls = vc ? NSStringFromClass([vc class]) : @"";
        // v7.7: GAD 广告一律放行（PRO 时长依赖 AdMob 完整流程，显示后由 viewDidAppear 秒关触发自然发奖）
        BOOL isGAD = cls.length > 0 && [cls hasPrefix:@"GAD"];
        BOOL isAd = cls.length > 0 && !isGAD && (
            [cls hasPrefix:@"UnityAds"] || [cls hasPrefix:@"Vungle"] || [cls hasPrefix:@"Liftoff"] ||
            [cls containsString:@"Interstitial"] || [cls containsString:@"Rewarded"] ||
            [cls containsString:@"AppOpen"]);
        if (isAd) {
            rivoAppendLog(@"AD-BLOCK: presentViewController 兜底拦截 %@", cls);
            return; // 广告不弹
        }
        if (isGAD) {
            rivoAppendLog(@"AD-BLOCK: GAD 广告放行（%s）0.4s 后发奖并自动关闭", cls.UTF8String);
            // v7.9: 0.4s 后——①从顶层 GAD VC 回溯广告对象触发奖励（KVC rewardHandler /
            // 模拟生命周期回调，App 收到奖励才能续时长，不再卡转圈）；②dismiss 广告（一闪而过）。
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                @try {
                    UIViewController *top = rivoTopPresentedVC();
                    NSString *topCls = top ? NSStringFromClass([top class]) : @"";
                    rivoAppendLog(@"AD-BLOCK: 0.4s 后顶层 VC = %@", topCls);
                    if (top && ([topCls hasPrefix:@"GAD"] ||
                                [topCls containsString:@"FullScreen"] || [topCls containsString:@"Ad"])) {
                        // 回溯广告对象（深度限制防环），先触发奖励
                        id ad = rivoFindRewardedAdInObject(top);
                        if (ad) {
                            rivoTriggerRewardSafe(ad);
                        } else {
                            rivoAppendLog(@"AD-BLOCK: 未回溯到广告对象 (top=%@)", topCls);
                        }
                        [top dismissViewControllerAnimated:NO completion:^{
                            rivoAppendLog(@"AD-BLOCK: GAD 广告已 dismiss，奖励已触发");
                        }];
                    } else if (top) {
                        rivoAppendLog(@"AD-BLOCK: 顶层非广告 VC（%@），不处理", topCls);
                    }
                } @catch (NSException *e) {
                    rivoAppendLog(@"AD-BLOCK: 自动发奖/关闭异常 %@", e);
                }
            });
        }
    } @catch (NSException *e) {
        rivoAppendLog(@"AD-BLOCK: rivoPresent 异常 %@", e);
    }
    if (origPresentIMP) {
        ((void (*)(id, SEL, id, BOOL, id))origPresentIMP)(self, _cmd, vc, animated, completion);
    } else {
        struct objc_super sup = { self, [UIViewController class] };
        ((void (*)(struct objc_super *, SEL, id, BOOL, id))objc_msgSendSuper)(&sup, _cmd, vc, animated, completion);
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

// （rivoJSONReentry / rivoConfigHandled 已在前文声明，避免前向使用编译错误）

static BOOL rivoLooksLikeConfigString(NSString *s) {
    if (s.length < 80) return NO;
    NSString *low = [s lowercaseString];
    // 加严：必须有明确的节点/配置特征，避免 AdMob gcache（"Server":"gvs"）误判
    return [low containsString:@"outbounds"] ||
           ([low containsString:@"\"uuid\""] && [low containsString:@"server_port"]) ||
           [low containsString:@"\"type\":\"vless\""] ||
           [low containsString:@"\"type\":\"vmess\""] ||
           [low containsString:@"\"type\":\"trojan\""] ||
           [low containsString:@"\"type\":\"shadowsocks\""] ||
           ([low containsString:@"\"server\""] && [low containsString:@"\"tag\""] &&
            [low containsString:@"\"port\""]);
}

static NSData *(*orig_NSJSON_dataWithJSONObject)(Class, SEL, id, NSJSONWritingOptions, NSError **);

static NSData *rivo_NSJSON_dataWithJSONObject(Class cls, SEL _cmd, id obj, NSJSONWritingOptions opt, NSError **err) {
    NSData *data = orig_NSJSON_dataWithJSONObject(cls, _cmd, obj, opt, err);
    @try {
        if (data.length > 120 && rivoJSONReentry == 0 && !rivoConfigHandled) {
            rivoJSONReentry++;
            NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (rivoLooksLikeConfigString(s) && !rivoIsDuplicate(data)) {
                rivoAppendLog(@"NSJSONSerialization serialize captured (%lu bytes)", (unsigned long)data.length);
                rivoHandleConfig(s, @"NSJSONSerialization serialize");
            }
            rivoJSONReentry--;
        }
    } @catch (NSException *e) {
        rivoJSONReentry = 0;
    }
    return data;
}

static id (*orig_NSJSON_JSONObjectWithData)(Class, SEL, NSData *, NSJSONReadingOptions, NSError **);

static id rivo_NSJSON_JSONObjectWithData(Class cls, SEL _cmd, NSData *data, NSJSONReadingOptions opt, NSError **err) {
    @try {
        if (data.length > 120 && rivoJSONReentry == 0 && !rivoConfigHandled) {
            rivoJSONReentry++;
            NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (rivoLooksLikeConfigString(s) && !rivoIsDuplicate(data)) {
                rivoAppendLog(@"NSJSONSerialization parse captured (%lu bytes)", (unsigned long)data.length);
                rivoHandleConfig(s, @"NSJSONSerialization parse");
            }
            rivoJSONReentry--;
        }
    } @catch (NSException *e) {
        rivoJSONReentry = 0;
    }
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

#pragma mark - 分步 CommonCrypto hook（CCCryptor*，Swift/CryptoKit 常用分步解密，CCCrypt 抓不到）

static void rivoCheckDecryptOutput(const void *out, size_t len) {
    if (!out || len < 80) return;
    NSString *str = [[NSString alloc] initWithBytes:out length:len encoding:NSUTF8StringEncoding];
    if (rivoLooksLikeConfigString(str)) {
        rivoAppendLog(@"CCCryptor decrypt output captured (%zu bytes)", len);
        rivoHandleConfig(str, @"CCCryptor* decrypt");
    }
}

// CCCryptorCreateWithMode
static CCCryptorStatus (*orig_CCCryptorCreateWithMode)(CCOperation, CCMode, CCAlgorithm, CCPadding,
                                                       const void *, size_t, const void *, size_t, const void *,
                                                       int, CCModeOptions, CCCryptorRef *);
static CCCryptorStatus rivo_CCCryptorCreateWithMode(CCOperation op, CCMode mode, CCAlgorithm alg, CCPadding pad,
                                                    const void *iv, size_t keyLength, const void *key,
                                                    size_t tweakLength, const void *tweak,
                                                    int numRounds, CCModeOptions options, CCCryptorRef *ref) {
    CCCryptorStatus st = orig_CCCryptorCreateWithMode(op, mode, alg, pad, iv, keyLength, key,
                                                      tweakLength, tweak, numRounds, options, ref);
    if (st == kCCSuccess && ref && *ref && op == kCCDecrypt) {
        rivoAppendLog(@"CCCryptorCreateWithMode decrypt created (alg=%d mode=%d)", (int)alg, (int)mode);
    }
    return st;
}

// CCCryptorUpdate
static CCCryptorStatus (*orig_CCCryptorUpdate)(CCCryptorRef, const void *, size_t, void *, size_t, size_t *);
static CCCryptorStatus rivo_CCCryptorUpdate(CCCryptorRef ref, const void *in, size_t inLen,
                                            void *out, size_t outAvail, size_t *outMoved) {
    CCCryptorStatus st = orig_CCCryptorUpdate(ref, in, inLen, out, outAvail, outMoved);
    if (st == kCCSuccess && out && outMoved && *outMoved > 80) {
        rivoCheckDecryptOutput(out, *outMoved);
    }
    return st;
}

// CCCryptorFinal
static CCCryptorStatus (*orig_CCCryptorFinal)(CCCryptorRef, void *, size_t, size_t *);
static CCCryptorStatus rivo_CCCryptorFinal(CCCryptorRef ref, void *out, size_t outAvail, size_t *outMoved) {
    CCCryptorStatus st = orig_CCCryptorFinal(ref, out, outAvail, outMoved);
    if (st == kCCSuccess && out && outMoved && *outMoved > 80) {
        rivoCheckDecryptOutput(out, *outMoved);
    }
    return st;
}

// CCCryptorGCM（AES-GCM 分步）
static CCCryptorStatus (*orig_CCCryptorGCM)(CCOperation, CCAlgorithm, const void *, size_t,
                                            const void *, const void *, size_t,
                                            const void *, size_t, void *, size_t *);
static CCCryptorStatus rivo_CCCryptorGCM(CCOperation op, CCAlgorithm alg, const void *key, size_t keyLength,
                                         const void *iv, const void *aData, size_t aDataLen,
                                         const void *in, size_t inLen, void *out, size_t *outMoved) {
    CCCryptorStatus st = orig_CCCryptorGCM(op, alg, key, keyLength, iv, aData, aDataLen, in, inLen, out, outMoved);
    if (st == kCCSuccess && op == kCCDecrypt && out && outMoved && *outMoved > 80) {
        rivoCheckDecryptOutput(out, *outMoved);
    }
    return st;
}

static void rivoHookCCCryptor(void) {
    rebind_symbols((struct rebinding[]){
        {"CCCryptorCreateWithMode", (void *)rivo_CCCryptorCreateWithMode, (void **)&orig_CCCryptorCreateWithMode},
        {"CCCryptorUpdate",         (void *)rivo_CCCryptorUpdate,         (void **)&orig_CCCryptorUpdate},
        {"CCCryptorFinal",          (void *)rivo_CCCryptorFinal,          (void **)&orig_CCCryptorFinal},
        {"CCCryptorGCM",            (void *)rivo_CCCryptorGCM,            (void **)&orig_CCCryptorGCM}
    }, 4);
    rivoAppendLog(@"CCCryptor* hooks installed");
}

#pragma mark - LibboxSetup C 函数 hook（sing-box 配置入口，dump 结构找明文）

static int (*orig_LibboxSetup)(void *options);

// 从可能的内存地址安全读取字符串（Go string = {char* ptr; int64 len;}，用 mach_vm_read 防崩溃）
static void rivoTryReadGoString(const unsigned char *mem, long offset) {
    unsigned long long ptr = 0;
    unsigned long long len = 0;
    memcpy(&ptr, mem + offset, 8);
    memcpy(&len, mem + offset + 8, 8);
    if (ptr < 0x10000 || len == 0 || len > 0x100000) return;
    if (ptr > 0x7fffffffffffULL) return;
    vm_offset_t data = 0;
    mach_msg_type_number_t cnt = 0;
    kern_return_t kr = rivoMachVmRead(mach_task_self(), (mach_vm_address_t)ptr, (mach_msg_type_number_t)len, &data, &cnt);
    if (kr != KERN_SUCCESS || cnt == 0) return;
    int printable = 1;
    for (unsigned long long i = 0; i < cnt; i++) {
        unsigned char c = ((unsigned char *)data)[i];
        if (c < 0x09 || (c > 0x0D && c < 0x20)) { printable = 0; break; }
    }
    if (printable && cnt >= 4) {
        NSString *s = [[NSString alloc] initWithBytes:(const void *)data length:cnt encoding:NSUTF8StringEncoding];
        if (s.length) {
            rivoAppendLog(@"LibboxSetup string[off=%ld len=%u]: %@", offset, cnt,
                          s.length > 400 ? [s substringToIndex:400] : s);
            if (rivoLooksLikeConfigString(s)) {
                rivoHandleConfig(s, @"LibboxSetup options");
            }
        }
    }
    vm_deallocate(mach_task_self(), data, cnt);
}

static int rivo_LibboxSetup(void *options) {
    rivoAppendLog(@">>> LibboxSetup called, options=%p", options);
    if (options) {
        const unsigned char *mem = (const unsigned char *)options;
        // 扫描 struct 前 1024 字节中的 Go string 字段（每 16 字节一个候选）
        for (long off = 0; off < 1024 - 16; off += 8) {
            @try {
                rivoTryReadGoString(mem, off);
            } @catch (NSException *e) {}
        }
        // 前 256 字节 hex dump
        NSMutableString *hex = [NSMutableString string];
        for (int i = 0; i < 256 && i < 1024; i++) {
            [hex appendFormat:@"%02X ", mem[i]];
            if (i % 16 == 15) [hex appendString:@"\n"];
        }
        rivoAppendLog(@"LibboxSetup options hex:\n%@", hex);
    }
    if (orig_LibboxSetup) {
        return orig_LibboxSetup(options);
    }
    return 0;
}

static void rivoHookLibboxSetup(void) {
    rebind_symbols((struct rebinding[]){
        {"LibboxSetup", (void *)rivo_LibboxSetup, (void **)&orig_LibboxSetup}
    }, 1);
    rivoAppendLog(@"LibboxSetup hook installed");
}

#pragma mark - 执行 hook

static void rivoDoHook(void) {
    static BOOL hooked = NO;
    if (hooked) return;
    hooked = YES;

    // 0) CCCrypt + NSJSONSerialization 已在 constructor 中 hook（勿重复，会递归）

    // 1) AdMob 广告：
    //    - 开屏/插屏/横幅：load 直接失败（零广告请求，不后台刷量）
    //    - 激励广告(GADRewardedAd)：不拦 load（App 需要它"加载成功"才能进入发奖流程），改拦展示层 present 直接发奖励
    Class gAppOpen = NSClassFromString(@"GADAppOpenAd");
    Class gInter = NSClassFromString(@"GADInterstitialAd");
    Class gRew = NSClassFromString(@"GADRewardedAd");
    Class gBanner = NSClassFromString(@"GADBannerView");

    SEL loadSel = NSSelectorFromString(@"loadWithAdUnitID:request:completionHandler:");
    if (gAppOpen) {
        Method m = class_getClassMethod(gAppOpen, loadSel);
        if (m) method_setImplementation(m, (IMP)rivoFailFullScreenLoad);
        Method mp = class_getInstanceMethod(gAppOpen, NSSelectorFromString(@"presentFromRootViewController:"));
        if (mp) method_setImplementation(mp, (IMP)rivoFullScreenPresent);
    }
    if (gInter) {
        Method m = class_getClassMethod(gInter, loadSel);
        if (m) method_setImplementation(m, (IMP)rivoFailFullScreenLoad);
        Method mp = class_getInstanceMethod(gInter, NSSelectorFromString(@"presentFromRootViewController:"));
        if (mp) method_setImplementation(mp, (IMP)rivoFullScreenPresent);
    }
    if (gRew) {
        // 激励不拦 load（保证 App 能拿到 ad 走发奖流程），只拦展示层
        Method mp = class_getInstanceMethod(gRew, NSSelectorFromString(@"presentFromRootViewController:userDidEarnRewardHandler:"));
        if (mp) method_setImplementation(mp, (IMP)rivoRewardPresent);
    }
    // v7.4: GADRewardedInterstitialAd（激励插屏，PRO 页常用）同样不拦 load、拦 present 直接发奖励
    Class gRewInter = NSClassFromString(@"GADRewardedInterstitialAd");
    if (gRewInter) {
        Method mp = class_getInstanceMethod(gRewInter, NSSelectorFromString(@"presentFromRootViewController:userDidEarnRewardHandler:"));
        if (mp) method_setImplementation(mp, (IMP)rivoRewardPresent);
    }
    if (gBanner) {
        Method m = class_getInstanceMethod(gBanner, @selector(loadRequest:));
        if (m) method_setImplementation(m, (IMP)rivoEmptyBannerLoad);
    }

    // 2) Unity Ads：不拦 load，拦 show（激励直接完成回调，PRO 时间照拿）
    Class unityAds = NSClassFromString(@"UnityAds");
    if (unityAds) {
        Method mu = class_getClassMethod(unityAds, NSSelectorFromString(@"show:showDelegate:"));
        if (mu) method_setImplementation(mu, (IMP)rivoUnityShow);
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

    // 4.5) 万能兜底：任何广告 VC 通过 presentViewController 弹全屏时直接拦截（含中介/遗漏 SDK）
    Method mpv = class_getInstanceMethod([UIViewController class], @selector(presentViewController:animated:completion:));
    if (mpv) {
        origPresentIMP = method_getImplementation(mpv);
        method_setImplementation(mpv, (IMP)rivoPresent);
    }

    // 4.6) v7.8: GAD 秒关已改由 rivoPresent 延迟 dismiss 承担（viewDidAppear hook 仅在
    // GADFullScreenAdViewController 自身实现该方法时才注册——避免替换到父类 UIViewController
    // 的实现而影响所有正常页面）
    Class gFullVC = NSClassFromString(@"GADFullScreenAdViewController");
    if (gFullVC) {
        BOOL ownMethod = NO;
        unsigned int mc = 0;
        Method *ml = class_copyMethodList(gFullVC, &mc);
        for (unsigned int i = 0; i < mc; i++) {
            if (method_getName(ml[i]) == @selector(viewDidAppear:)) { ownMethod = YES; break; }
        }
        if (ml) free(ml);
        if (ownMethod) {
            Method mv = class_getInstanceMethod(gFullVC, @selector(viewDidAppear:));
            if (mv) {
                origGADVCViewDidAppearIMP = method_getImplementation(mv);
                method_setImplementation(mv, (IMP)rivoGADVCViewDidAppear);
            }
        }
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
    rivoHookCCCryptor();
    rivoHookLibboxSetup();
    rivoHookNSJSON();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
                       rivoTryHook(0);
                   });
}
