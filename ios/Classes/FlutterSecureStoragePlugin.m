#import "FlutterSecureStoragePlugin.h"

static NSString *const KEYCHAIN_SERVICE = @"flutter_secure_storage_service";
static NSString *const CHANNEL_NAME = @"plugins.it_nomads.com/flutter_secure_storage";

static NSString *const InvalidParameters = @"Invalid parameter's type";

@interface FlutterSecureStoragePlugin()

@property (strong, nonatomic) NSDictionary *query;

@end

@implementation FlutterSecureStoragePlugin

+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
    FlutterMethodChannel* channel = [FlutterMethodChannel
                                     methodChannelWithName:CHANNEL_NAME
                                     binaryMessenger:[registrar messenger]];
    FlutterSecureStoragePlugin* instance = [[FlutterSecureStoragePlugin alloc] init];
    [registrar addMethodCallDelegate:instance channel:channel];
}

- (void)handleMethodCall:(FlutterMethodCall*)call result:(FlutterResult)result {
    NSDictionary *arguments = [call arguments];
    NSDictionary *options = [arguments[@"options"] isKindOfClass:[NSDictionary class]] ? arguments[@"options"] : nil;
    NSString *key = arguments[@"key"];

    if ([@"read" isEqualToString:call.method]) {
        result([self read:key withOptions:options]);
    } else
    if ([@"write" isEqualToString:call.method]) {
        NSString *value = arguments[@"value"];
        if (![value isKindOfClass:[NSString class]]) {
            result(InvalidParameters);
            return;
        }
        [self write:value forKey:key withOptions:options];
        result(nil);
    } else if ([@"delete" isEqualToString:call.method]) {
        [self delete:key withOptions:options];
        result(nil);
    } else if ([@"deleteAll" isEqualToString:call.method]) {
        [self deleteAll:options];
        result(nil);
    } else if ([@"readAll" isEqualToString:call.method]) {
        result([self readAll:options]);
    } else {
        result(FlutterMethodNotImplemented);
    }
}

- (NSMutableDictionary *)_queryWithKey:(NSString *)key withOptions:(NSDictionary *)options {
    NSMutableDictionary *query = [self _query:options];
    query[(__bridge id)kSecAttrAccount] = [key dataUsingEncoding:NSUTF8StringEncoding];

    return query;
}

- (NSMutableDictionary *)_query:(NSDictionary *)options {
    NSString *service = KEYCHAIN_SERVICE;
    NSString *serviceOption = options[@"keychainService"];
    if (serviceOption != (id)[NSNull null] && [serviceOption length] > 0) {
        service = serviceOption;
    }
    NSMutableDictionary *query = [@{
                                    (__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
                                    (__bridge id)kSecAttrService:service,
                                    } mutableCopy];

    NSString *groupId = options[@"groupId"];
    if (groupId != (id)[NSNull null] && [groupId length] > 0) {
        query[(__bridge id)kSecAttrAccessGroup] = groupId;
    }

    return query;
}

- (void)write:(NSString *)value forKey:(NSString *)key withOptions:(NSDictionary *)options {
    NSMutableDictionary *search = [self _queryWithKey:key withOptions:options];
    search[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    
    OSStatus status;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)search, NULL);
    if (status == noErr){
        search[(__bridge id)kSecMatchLimit] = nil;
        
        NSDictionary *update = @{(__bridge id)kSecValueData: [value dataUsingEncoding:NSUTF8StringEncoding]};
        
        status = SecItemUpdate((__bridge CFDictionaryRef)search, (__bridge CFDictionaryRef)update);
        if (status != noErr){
            NSLog(@"SecItemUpdate status = %d", (int) status);
        }
    } else {
        search[(__bridge id)kSecValueData] = [value dataUsingEncoding:NSUTF8StringEncoding];
        search[(__bridge id)kSecMatchLimit] = nil;
        
        status = SecItemAdd((__bridge CFDictionaryRef)search, NULL);
        if (status != noErr){
            NSLog(@"SecItemAdd status = %d", (int) status);
        }
    }
}

- (NSString *)read:(NSString *)key withOptions:(NSDictionary *)options {
    NSMutableDictionary *search = [self _queryWithKey:key withOptions:options];
    search[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
    
    CFDataRef resultData = NULL;
    
    OSStatus status;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)search, (CFTypeRef*)&resultData);
    NSString *value;
    if (status == noErr){
        NSData *data = (__bridge NSData*)resultData;
        value = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    } else {
        NSLog(@"read status = %d", (int) status);
    }
    
    return value;
}

- (void)delete:(NSString *)key withOptions:(NSDictionary *)options {
    NSMutableDictionary *search = [self _queryWithKey:key withOptions:options];
    search[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
    
    SecItemDelete((__bridge CFDictionaryRef)search);
}

- (void)deleteAll:(NSDictionary *)options {
    NSMutableDictionary *search = [self _query:options];
    SecItemDelete((__bridge CFDictionaryRef)search);
}

- (NSDictionary *)readAll:(NSDictionary *)options {
    NSMutableDictionary *search = [self _query:options];

    search[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;

    search[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    search[(__bridge id)kSecReturnAttributes] = (__bridge id)kCFBooleanTrue;

    CFArrayRef resultData = NULL;
    
    OSStatus status;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)search, (CFTypeRef*)&resultData);
    if (status == noErr){
        NSArray *items = (__bridge NSArray*)resultData;
        
        NSMutableDictionary *results = [[NSMutableDictionary alloc] init];
        for (NSDictionary *item in items){
            NSString *key = item[(__bridge NSString *)kSecAttrAccount];
            NSString *value = [[NSString alloc] initWithData:item[(__bridge NSString *)kSecValueData] encoding:NSUTF8StringEncoding];
            results[key] = value;
        }
        return [results copy];
    }
    
    return @{};
}

@end
