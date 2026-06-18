/******************************************************************************
 *   Copyright (C) 2016 Mathias Hasselmann <mathias.hasselmann@kdab.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/

#include "keychain_p.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>

using namespace QKeychain;

struct ErrorDescription
{
    QKeychain::Error code;
    QString message;

    ErrorDescription(QKeychain::Error code, const QString &message) : code(code), message(message)
    {
    }

    static ErrorDescription fromStatus(OSStatus status)
    {
        switch (status) {
        case errSecSuccess:
            return ErrorDescription(QKeychain::NoError, Job::tr("No error"));
        case errSecItemNotFound:
            return ErrorDescription(
                    QKeychain::EntryNotFound,
                    Job::tr("The specified item could not be found in the keychain"));
        case errSecUserCanceled:
            return ErrorDescription(QKeychain::AccessDeniedByUser,
                                    Job::tr("User canceled the operation"));
        case errSecInteractionNotAllowed:
            return ErrorDescription(QKeychain::AccessDenied,
                                    Job::tr("User interaction is not allowed"));
        case errSecNotAvailable:
            return ErrorDescription(
                    QKeychain::AccessDenied,
                    Job::tr("No keychain is available. You may need to restart your computer"));
        case errSecAuthFailed:
            return ErrorDescription(
                    QKeychain::AccessDenied,
                    Job::tr("The user name or passphrase you entered is not correct"));
        case errSecVerifyFailed:
            return ErrorDescription(QKeychain::AccessDenied,
                                    Job::tr("A cryptographic verification failure has occurred"));
        case errSecUnimplemented:
            return ErrorDescription(QKeychain::NotImplemented,
                                    Job::tr("Function or operation not implemented"));
        case errSecIO:
            return ErrorDescription(QKeychain::OtherError, Job::tr("I/O error"));
        case errSecOpWr:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("Already open with with write permission"));
        case errSecParam:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("Invalid parameters passed to a function"));
        case errSecAllocate:
            return ErrorDescription(QKeychain::OtherError, Job::tr("Failed to allocate memory"));
        case errSecBadReq:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("Bad parameter or invalid state for operation"));
        case errSecInternalComponent:
            return ErrorDescription(QKeychain::OtherError, Job::tr("An internal component failed"));
        case errSecDuplicateItem:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("The specified item already exists in the keychain"));
        case errSecDecode:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("Unable to decode the provided data"));
        }

        return ErrorDescription(QKeychain::OtherError, Job::tr("Unknown error"));
    }
};

@interface AppleKeychainInterface : NSObject

- (instancetype)initWithJob:(Job *)job andPrivateJob:(JobPrivate *)privateJob;
- (void)keychainTaskFinished;
- (void)keychainReadTaskFinished:(NSData *)retrievedData withAccount:(NSString *)account;
- (void)keychainTaskFinishedWithError:(OSStatus)status
                   descriptiveMessage:(NSString *)descriptiveMessage;

@end

@interface AppleKeychainInterface () {
    QPointer<Job> _job;
    QPointer<JobPrivate> _privateJob;
}
@end

@implementation AppleKeychainInterface

- (instancetype)initWithJob:(Job *)job andPrivateJob:(JobPrivate *)privateJob
{
    self = [super init];
    if (self) {
        _job = job;
        _privateJob = privateJob;
    }
    return self;
}

- (void)dealloc
{
    [NSNotificationCenter.defaultCenter removeObserver:self];
    [super dealloc];
}

- (void)keychainTaskFinished
{
    if (_job) {
        _job->emitFinished();
    }
}

- (void)keychainReadTaskFinished:(NSData *)retrievedData withAccount:(NSString *)account
{
    if (_privateJob) {
        _privateJob->data.clear();
        _privateJob->mode = JobPrivate::Binary;
        if (retrievedData != nil) {
            _privateJob->data = QByteArray::fromNSData(retrievedData);
        }
    }

    if (_job) {
        if (account != nil) {
            _job->setKey(QString::fromNSString(account));
        }
        _job->emitFinished();
    }
}

- (void)keychainTaskFinishedWithError:(OSStatus)status
                   descriptiveMessage:(NSString *)descriptiveMessage
{
    const auto localisedDescriptiveMessage = Job::tr([descriptiveMessage UTF8String]);

    const ErrorDescription error = ErrorDescription::fromStatus(status);
    const auto messageWithCode =
            QStringLiteral("%1 (OSStatus %2)").arg(error.message).arg(static_cast<long>(status));
    const auto fullMessage = localisedDescriptiveMessage.isEmpty()
            ? messageWithCode
            : QStringLiteral("%1: %2").arg(localisedDescriptiveMessage, messageWithCode);

    if (_job) {
        _job->emitFinishedWithError(error.code, fullMessage);
    }
}

@end

static void StartReadPassword(const QString &service, const QString &key,
                              AppleKeychainInterface *const interface)
{
    Q_UNUSED(key)
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        // Read by service name only: return the data along with the item's
        // attributes so the account (username) can be reported back as the key.
        NSDictionary *const query = @{
            (__bridge NSString *)kSecClass : (__bridge NSString *)kSecClassGenericPassword,
            (__bridge NSString *)kSecAttrService : service.toNSString(),
            (__bridge NSString *)kSecReturnData : @YES,
            (__bridge NSString *)kSecReturnAttributes : @YES,
        };

        CFTypeRef resultRef = nil;
        const OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &resultRef);

        if (status == errSecSuccess) {
            NSDictionary *const result = (__bridge NSDictionary *)resultRef;
            NSData *const data = result[(__bridge NSString *)kSecValueData];
            NSString *const account = result[(__bridge NSString *)kSecAttrAccount];
            dispatch_async(dispatch_get_main_queue(), ^{
                [interface keychainReadTaskFinished:data withAccount:account];
                [interface release];
            });
        } else {
            NSString *const descriptiveErrorString =
                    @"Could not retrieve private key from keystore";
            dispatch_async(dispatch_get_main_queue(), ^{
                [interface keychainTaskFinishedWithError:status
                                      descriptiveMessage:descriptiveErrorString];
                [interface release];
            });
        }

        if (resultRef) {
            CFRelease(resultRef);
        }
    });
}

static void StartWritePassword(const QString &service, const QString &key, const QByteArray &data,
                               AppleKeychainInterface *const interface)
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSDictionary *const query = @{
            (__bridge NSString *)kSecClass : (__bridge NSString *)kSecClassGenericPassword,
            (__bridge NSString *)kSecAttrService : service.toNSString(),
            (__bridge NSString *)kSecAttrAccount : key.toNSString(),
        };

        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, nil);

        if (status == errSecSuccess) {
            NSDictionary *const update = @{
                (__bridge NSString *)kSecValueData : data.toNSData(),
            };

            status = SecItemUpdate((__bridge CFDictionaryRef)query,
                                   (__bridge CFDictionaryRef)update);
        } else {
            NSDictionary *const insert = @{
                (__bridge NSString *)kSecClass : (__bridge NSString *)kSecClassGenericPassword,
                (__bridge NSString *)kSecAttrService : service.toNSString(),
                (__bridge NSString *)kSecAttrAccount : key.toNSString(),
                (__bridge NSString *)kSecValueData : data.toNSData(),
            };

            status = SecItemAdd((__bridge const CFDictionaryRef)insert, nil);
        }

        if (status == errSecSuccess) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [interface keychainTaskFinished];
                [interface release];
            });
        } else {
            NSString *const descriptiveErrorString = @"Could not store data in settings";

            dispatch_async(dispatch_get_main_queue(), ^{
                [interface keychainTaskFinishedWithError:status
                                      descriptiveMessage:descriptiveErrorString];
                [interface release];
            });
        }
    });
}

static void StartDeletePassword(const QString &service, const QString &key,
                                AppleKeychainInterface *const interface)
{
    Q_UNUSED(key)
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        // Delete by service name only, regardless of the account (username).
        //
        // A single SecItemDelete call with a service-only query fails on the legacy
        // macOS keychain when more than one item matches (OSStatus -25244,
        // errSecInvalidOwnerEdit). Resolve every matching item to its own reference
        // and delete them one at a time instead.
        NSDictionary *const findQuery = @{
            (__bridge NSString *)kSecClass : (__bridge NSString *)kSecClassGenericPassword,
            (__bridge NSString *)kSecAttrService : service.toNSString(),
            (__bridge NSString *)kSecMatchLimit : (__bridge NSString *)kSecMatchLimitAll,
            (__bridge NSString *)kSecReturnRef : @YES,
        };

        CFTypeRef resultRef = nil;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)findQuery, &resultRef);

        if (status == errSecSuccess) {
            NSArray *const items = (__bridge NSArray *)resultRef;
            for (id item in items) {
                NSDictionary *const deleteQuery = @{
                    (__bridge NSString *)kSecValueRef : item,
                };
                status = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
                if (status != errSecSuccess) {
                    break;
                }
            }
        }

        if (resultRef) {
            CFRelease(resultRef);
        }

        if (status == errSecSuccess) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [interface keychainTaskFinished];
                [interface release];
            });
        } else {
            NSString *const descriptiveErrorString = @"Could not remove private key from keystore";
            dispatch_async(dispatch_get_main_queue(), ^{
                [interface keychainTaskFinishedWithError:status
                                      descriptiveMessage:descriptiveErrorString];
                [interface release];
            });
        }
    });
}

void ReadPasswordJobPrivate::scheduledStart()
{
    AppleKeychainInterface *const interface = [[AppleKeychainInterface alloc] initWithJob:q
                                                                            andPrivateJob:this];
    StartReadPassword(service, key, interface);
}

void WritePasswordJobPrivate::scheduledStart()
{
    AppleKeychainInterface *const interface = [[AppleKeychainInterface alloc] initWithJob:q
                                                                            andPrivateJob:this];
    StartWritePassword(service, key, data, interface);
}

void DeletePasswordJobPrivate::scheduledStart()
{
    AppleKeychainInterface *const interface = [[AppleKeychainInterface alloc] initWithJob:q
                                                                            andPrivateJob:this];
    StartDeletePassword(service, key, interface);
}

bool QKeychain::isAvailable()
{
    return true;
}
