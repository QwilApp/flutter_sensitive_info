#import "SensitiveInfoPlugin.h"
#import <LocalAuthentication/LocalAuthentication.h>

CFStringRef convertkSecAttrAccessible(NSString *key) {
    if ([key isEqual:@"kSecAttrAccessibleAfterFirstUnlock"]) {
        return kSecAttrAccessibleAfterFirstUnlock;
    }
    if ([key isEqual:@"kSecAttrAccessibleAlways"]) {
        return kSecAttrAccessibleAlways;
    }
    if ([key isEqual:@"kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly"]) {
        return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly;
    }
    if ([key isEqual:@"kSecAttrAccessibleWhenUnlockedThisDeviceOnly"]) {
        return kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
    }
    if ([key isEqual:@"kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"]) {
        return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    }
    if ([key isEqual:@"kSecAttrAccessibleAlwaysThisDeviceOnly"]) {
        return kSecAttrAccessibleAlwaysThisDeviceOnly;
    }
    return kSecAttrAccessibleWhenUnlocked;
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "UnavailableInDeploymentTarget"

enum SecAccessControlCreateFlags convertkSecAccessControl(NSString *key) {
    if ([key isEqual:@"kSecAccessControlApplicationPassword"]) {
        if (@available(iOS 9.0, *)) {
            return kSecAccessControlApplicationPassword;
        }
    }
    if ([key isEqual:@"kSecAccessControlPrivateKeyUsage"]) {
        if (@available(iOS 9.0, *)) {
            return kSecAccessControlPrivateKeyUsage;
        }
    }
    if ([key isEqual:@"kSecAccessControlDevicePasscode"]) {
        if (@available(iOS 9.0, *)) {
            return kSecAccessControlDevicePasscode;
        }
    }
    if ([key isEqual:@"kSecAccessControlTouchIDAny"]) {
        if (@available(iOS 9.0, *)) {
            return kSecAccessControlTouchIDAny;
        }
    }
    if ([key isEqual:@"kSecAccessControlBiometryAny"]) {
        if (@available(iOS 11.3, *)) {
            return kSecAccessControlBiometryAny;
        } else if (@available(iOS 9.0, *)) {
            return kSecAccessControlTouchIDAny;
        }
    }
    if ([key isEqual:@"kSecAccessControlTouchIDCurrentSet"]) {
        if (@available(iOS 9.0, *)) {
            return kSecAccessControlTouchIDCurrentSet;
        }
    }
    if ([key isEqual:@"kSecAccessControlBiometryCurrentSet"]) {
        if (@available(iOS 11.3, *)) {
            return kSecAccessControlBiometryCurrentSet;
        } else if (@available(iOS 9.0, *)) {
            return kSecAccessControlTouchIDCurrentSet;
        }
    }
    return kSecAccessControlUserPresence;
}

#pragma clang diagnostic pop

// Messages from the comments in <Security/SecBase.h>
NSString *messageForError(NSError *error) {
    switch (error.code) {
        case errSecUnimplemented:
            return @"Function or operation not implemented.";

        case errSecIO:
            return @"I/O error.";

        case errSecOpWr:
            return @"File already open with with write permission.";

        case errSecParam:
            return @"One or more parameters passed to a function where not valid.";

        case errSecAllocate:
            return @"Failed to allocate memory.";

        case errSecUserCanceled:
            return @"User canceled the operation.";

        case errSecBadReq:
            return @"Bad parameter or invalid state for operation.";

        case errSecNotAvailable:
            return @"No keychain is available. You may need to restart your computer.";

        case errSecDuplicateItem:
            return @"The specified item already exists in the keychain.";

        case errSecItemNotFound:
            return @"The specified item could not be found in the keychain.";

        case errSecInteractionNotAllowed:
            return @"User interaction is not allowed.";

        case errSecDecode:
            return @"Unable to decode the provided data.";

        case errSecAuthFailed:
            return @"The user name or passphrase you entered is not correct.";

        default:
            return error.localizedDescription;
    }
}

@interface NSError (FlutterError)
@property(readonly, nonatomic) FlutterError *flutterError;
@end

@implementation NSError (FlutterError)
- (FlutterError *)flutterError {
    return [FlutterError errorWithCode:[NSString stringWithFormat:@"Error %d", (int) self.code]
                               message:messageForError(self)
                               details:self.localizedDescription];
}

@end

@implementation SensitiveInfoPlugin

+ (void)registerWithRegistrar:(NSObject <FlutterPluginRegistrar> *)registrar {
    FlutterMethodChannel *channel = [FlutterMethodChannel
            methodChannelWithName:@"io.qwil/sensitive_info"
                  binaryMessenger:[registrar messenger]];
    SensitiveInfoPlugin *instance = [[SensitiveInfoPlugin alloc] init];
    [registrar addMethodCallDelegate:instance channel:channel];
}

- (void)handleMethodCall:(FlutterMethodCall *)methodCall result:(FlutterResult)result {
    if ([@"isSensorAvailable" isEqualToString:methodCall.method]) {
        [self isSensorAvailable:result];
    } else if ([@"getItem" isEqualToString:methodCall.method]) {
        [self getItem:methodCall result:result];
    } else if ([@"setItem" isEqualToString:methodCall.method]) {
        [self setItem:methodCall result:result];
    } else if ([@"deleteItem" isEqualToString:methodCall.method]) {
        [self deleteItem:methodCall result:result];
    } else if ([@"getAllItems" isEqualToString:methodCall.method]) {
        [self getAllItems:methodCall result:result];
    } else if ([@"cancelFingerprintAuth" isEqualToString:methodCall.method]) {
        result(NULL);
    } else {
        result(FlutterMethodNotImplemented);
    }
}

- (void)isSensorAvailable:(FlutterResult)resolve {
    LAContext *context = [[LAContext alloc] init];

    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:NULL]) {
        if (@available(iOS 11, *)) {
            if (context.biometryType == LABiometryTypeFaceID) {
                return resolve(@"Face ID");
            }
        }
        resolve(@"Touch ID");
    } else {
        resolve(@"none");
    }
}

- (void)getItem:(FlutterMethodCall *)methodCall result:(FlutterResult)result {
    NSString *keychainName = methodCall.arguments[@"keychainName"];
    NSString *key = methodCall.arguments[@"key"];

    // Create dictionary of search parameters
    NSMutableDictionary *query = [@{(__bridge id) kSecClass: (__bridge id) kSecClassGenericPassword,
            (__bridge id) kSecAttrService: keychainName,
            (__bridge id) kSecAttrAccount: key,
            (__bridge id) kSecReturnAttributes: (__bridge id) kCFBooleanTrue,
            (__bridge id) kSecReturnData: (__bridge id) kCFBooleanTrue} mutableCopy];

    if (methodCall.arguments[@"kSecUseOperationPrompt"] != NULL) {
        [query setValue:methodCall.arguments[@"kSecUseOperationPrompt"] forKey:(NSString *) kSecUseOperationPrompt];
    }

    // Look up server in the keychain
    NSDictionary *found = nil;
    CFTypeRef foundTypeRef = NULL;
    OSStatus osStatus = SecItemCopyMatching((__bridge CFDictionaryRef) query, &foundTypeRef);

    if (osStatus != noErr && osStatus != errSecItemNotFound) {
        FlutterError *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:osStatus userInfo:nil].flutterError;
        result(error);
        return;
    }

    found = (__bridge NSDictionary *) (foundTypeRef);
    if (!found) {
        result(NULL);
    } else {
        // Found
        NSString *value = [[NSString alloc] initWithData:found[(__bridge id) (kSecValueData)] encoding:NSUTF8StringEncoding];
        result(value);
    }
}

- (void)setItem:(FlutterMethodCall *)methodCall result:(FlutterResult)result {
    NSString *keychainName = methodCall.arguments[@"keychainName"];
    NSString *key = methodCall.arguments[@"key"];
    NSString *value = methodCall.arguments[@"value"];

    NSData *valueData = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary *query = [@{(__bridge id) kSecClass: (__bridge id) kSecClassGenericPassword,
            (__bridge id) kSecAttrService: keychainName,
            (__bridge id) kSecValueData: valueData,
            (__bridge id) kSecAttrAccount: key} mutableCopy];

    if (methodCall.arguments[@"biometric"]) {
        SecAccessControlCreateFlags kSecAccessControlValue = convertkSecAccessControl(methodCall.arguments[@"kSecAccessControl"]);
        SecAccessControlRef sac = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, kSecAccessControlValue, NULL);
        [query setValue:(__bridge id _Nullable) (sac) forKey:(NSString *) kSecAttrAccessControl];
    } else if (methodCall.arguments[@"kSecAttrAccessible"] != NULL) {
        CFStringRef kSecAttrAccessibleValue = convertkSecAttrAccessible(methodCall.arguments[@"kSecAttrAccessible"]);
        [query setValue:(__bridge id _Nullable) (kSecAttrAccessibleValue) forKey:(NSString *) kSecAttrAccessible];
    }

    SecItemDelete((__bridge CFDictionaryRef) query);
    OSStatus osStatus = SecItemAdd((__bridge CFDictionaryRef) query, NULL);
    if (osStatus != noErr) {
        FlutterError *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:osStatus userInfo:nil].flutterError;
        result(error);
    } else {
        result(NULL);
    }
}

- (void)deleteItem:(FlutterMethodCall *)methodCall result:(FlutterResult)result {
    NSString *key = methodCall.arguments[@"key"];
    NSString *keychainName = methodCall.arguments[@"keychainName"];

    // Create dictionary of search parameters
    NSDictionary *query = @{(__bridge id) kSecClass: (__bridge id) kSecClassGenericPassword,
            (__bridge id) kSecAttrService: keychainName,
            (__bridge id) kSecAttrAccount: key,
            (__bridge id) kSecReturnAttributes: (__bridge id) kCFBooleanTrue,
            (__bridge id) kSecReturnData: (__bridge id) kCFBooleanTrue};

    // Remove any old values from the keychain
    OSStatus osStatus = SecItemDelete((__bridge CFDictionaryRef) query);
    if (osStatus != noErr && osStatus != errSecItemNotFound) {
        FlutterError *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:osStatus userInfo:nil].flutterError;
        result(error);
        return;
    }
    result(NULL);
}

- (void)getAllItems:(FlutterMethodCall *)methodCall result:(FlutterResult)flutterResult {
    NSString *keychainName = methodCall.arguments[@"keychainName"];

    NSMutableDictionary *finalResult = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *query = [@{(__bridge id) kSecReturnAttributes: (__bridge id) kCFBooleanTrue,
            (__bridge id) kSecMatchLimit: (__bridge id) kSecMatchLimitAll,
            (__bridge id) kSecReturnData: (__bridge id) kCFBooleanTrue} mutableCopy];

    if (keychainName != NULL) query[(NSString *) kSecAttrService] = keychainName;

    NSArray *secItemClasses = @[(__bridge id) kSecClassGenericPassword,
            (__bridge id) kSecClassInternetPassword,
            (__bridge id) kSecClassCertificate,
            (__bridge id) kSecClassKey,
            (__bridge id) kSecClassIdentity];


    for (id secItemClass in secItemClasses) {
        query[(__bridge id) kSecClass] = secItemClass;

        CFTypeRef result = NULL;

        SecItemCopyMatching((__bridge CFDictionaryRef) query, &result);

        if (result != NULL) {
            for (NSDictionary *item in (__bridge id) result) {
                finalResult[(NSString *) item[(__bridge id) (kSecAttrAccount)]]
                        = [[NSString alloc] initWithData:item[(__bridge id) (kSecValueData)] encoding:NSUTF8StringEncoding];
            }
        }
    }

    if (finalResult != nil) {
        flutterResult(finalResult);
    } else {
        flutterResult([FlutterError errorWithCode:@"no_events" message:@"There were no events" details:nil]);
    }
}

@end

