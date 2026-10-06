#import <UIKit/UIKit.h>

// ===== RivoVPNAD: 方案A（广告加载失败触发官方免费解锁）+ 节点自动抓取解析 =====

#pragma mark - 广告屏蔽：加载直接失败（触发 App 官方兜底解锁）

static NSError *rivoAdBlockError(void) {
    return [NSError errorWithDomain:@"com.rivo.adblock"
                               code:1
                           userInfo:@{NSLocalizedDescriptionKey: @"Ad blocked by RivoVPNAD"}];
}

%hook GADAppOpenAd
+ (void)loadWithAdUnitID:(id)adUnitID request:(id)request completionHandler:(id)handler {
    void (^completion)(id, NSError *) = handler;
    if (completion) completion(nil, rivoAdBlockError());
}
%end

%hook GADInterstitialAd
+ (void)loadWithAdUnitID:(id)adUnitID request:(id)request completionHandler:(id)handler {
    void (^completion)(id, NSError *) = handler;
    if (completion) completion(nil, rivoAdBlockError());
}
%end

%hook GADRewardedAd
+ (void)loadWithAdUnitID:(id)adUnitID request:(id)request completionHandler:(id)handler {
    void (^completion)(id, NSError *) = handler;
    if (completion) completion(nil, rivoAdBlockError());
}
%end

%hook GADBannerView
- (void)loadRequest:(id)request {
}
%end

#pragma mark - 节点抓取：拦截 RivoVPN 官方 API 响应

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
        // Trojan: password 且带 sni
        NSString *tp = [NSString stringWithFormat:@"%@:%@@%@:%@?peer=%@#%@",
                        uuid, passwd, host, port, sni ?: @"", nameB64];
        return [@"trojan://" stringByAppendingString:tp];
    }
    if (uuid) {
        // VLESS: 有 uuid 无 alterId 或 alterId=0
        if (alterId && [alterId intValue] > 0) {
            // VMess
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
        // Shadowsocks
        NSString *userinfo = [[NSString stringWithFormat:@"%@:%@", method, passwd] dataUsingEncoding:NSUTF8StringEncoding];
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
        // 优先按常见容器名找
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
        // 自身可能就是节点
        NSString *uri = rivoURIFromDict(d);
        if (uri && ![uris containsObject:uri]) [uris addObject:uri];
    }
}

static void rivoShowAlert(NSString *title, NSString *msg) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIApplication *app = [UIApplication sharedApplication];
        UIWindow *win = app.keyWindow;
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
    if (err || !obj) {
        // 不是 JSON 也存一份原始数据
        return;
    }
    NSMutableArray *uris = [NSMutableArray array];
    rivoCollectNodes(obj, uris, 0);

    // 原始响应存 Documents
    NSString *home = NSHomeDirectory();
    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    NSString *rawPath = [docDir stringByAppendingPathComponent:@"rivo_nodes_raw.json"];
    [data writeToFile:rawPath atomically:YES];

    if (uris.count == 0) {
        // 没解析出节点，原始 JSON 也复制一份方便人工检查
        NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        UIPasteboard *pb = [UIPasteboard generalPasteboard];
        pb.string = raw;
        rivoShowAlert(@"RivoVPNAD", [NSString stringWithFormat:@"已复制原始数据(%lu字节)到剪贴板，节点结构待适配\n%@", (unsigned long)data.length, url]);
        return;
    }

    // 生成订阅文本：每行一个 URI
    NSString *subText = [uris componentsJoinedByString:@"\n"];
    NSData *subData = [subText dataUsingEncoding:NSUTF8StringEncoding];
    NSString *subB64 = [[subData base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
    NSString *subLink = [@"sub://" stringByAppendingString:subB64];

    // 剪贴板复制订阅链接
    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    pb.string = subLink;

    // 订阅文本也存一份
    [subText writeToFile:[docDir stringByAppendingPathComponent:@"rivo_sub.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];

    rivoShowAlert(@"RivoVPNAD", [NSString stringWithFormat:@"已抓取 %lu 个节点，订阅链接已复制到剪贴板\nShadowrocket 中粘贴即可导入", (unsigned long)uris.count]);
}

#pragma mark - hook NSURLSession 拦截响应

%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData * _Nullable, NSURLResponse * _Nullable, NSError * _Nullable))completionHandler {
    NSString *u = request.URL.absoluteString;
    if (rivoIsTargetURL(u)) {
        void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
            if (completionHandler) completionHandler(data, resp, err);
            if (data.length) rivoSaveNodes(data, u);
        };
        return %orig(request, wrapped);
    }
    return %orig;
}
%end
