/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 ROM security subsystem — rewritten from Ghidra decompilation of Switzach v1.0.5
 ROM/System/Rom/init (4312 functions, 133K lines C pseudocode).

 This integrates the ROM seal/verify/rollback protection that Switzach ships
 but upstream Nyxian lacks. All logic is reimplemented from the decompiled
 pseudocode at workspace/switzach_re/decomp_init.c.

 Key functions ported:
   NXROMVerifySeal        @0x7810
   NXROMVerifySealedFile  @0x7d70
   NXROMSealDomain        (domain separation for HMAC)
   NXROMSealMAC           (HMAC-SHA256 over domain||data)
   NXROMDeviceVerify      @0x81ec
   NXROMDeviceKey         (per-device key derivation)
   NXROMDeviceSigningContext @0x8524
   NXROMDeviceCheckRollback   @0x8350
   NXROMDeviceReleaseProof    @0x8478
   NXROMRollbackCheck     @0x91fc
   NXROMParseSecurityVersion @0x9134
   NXROMArchiveProof      @0x6d08
   NXROMArchiveProofForFD @0x6740
   NXROMStageVerifiedArchive @0x9f20
   NXROMSealedReleaseProof / NXROMSealedReleaseIdentity
   NXROMSlotPath / NXSlotInit / NXSlotMain / NXSlotCreateWindow / NXSlotDisappear
*/

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString * const NXROMPublicKey;
extern NSString * const NXROMDeviceKey;

#pragma mark - Security Version Parsing

/// Parses a semantic version string "major.minor.patch" into a comparable integer.
/// Decompiled from NXROMParseSecurityVersion @0x9134.
static inline NSUInteger NXROMParseSecurityVersion(NSString *version) {
    NSArray<NSString *> *parts = [version componentsSeparatedByString:@"."];
    NSUInteger major = 0, minor = 0, patch = 0;
    if (parts.count > 0) major = [parts[0] NSUIntegerValue];
    if (parts.count > 1) minor = [parts[1] NSUIntegerValue];
    if (parts.count > 2) patch = [parts[2] NSUIntegerValue];
    return (major << 20) | (minor << 10) | patch;
}

#pragma mark - Seal MAC (HMAC domain separation)

/// Computes HMAC-SHA256 over domain||data.
/// Decompiled from NXROMSealMAC — domain separation prevents cross-protocol replay.
static inline NSData * NXROMSealMAC(NSString *domain, NSData *key, NSData *data) {
    const char *dom = [domain UTF8String];
    NSUInteger domLen = strlen(dom);
    NSMutableData *payload = [NSMutableData dataWithCapacity:domLen + data.length];
    [payload appendBytes:dom length:domLen];
    [payload appendData:data];

    unsigned char mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, payload.bytes, payload.length, mac);
    return [NSData dataWithBytes:mac length:CC_SHA256_DIGEST_LENGTH];
}

#pragma mark - Seal Verification

/// Verifies a ROM seal: the seal blob is {domain_tag(8) || mac(32) || payload(N)}.
/// Decompiled from NXROMVerifySeal @0x7810.
/// Returns YES if the MAC verifies against the key for the given domain.
BOOL NXROMVerifySeal(NSData *sealBlob, NSString *expectedDomain, NSData *verificationKey);

/// Verifies a sealed file: reads file, computes seal MAC, compares against embedded seal.
/// Decompiled from NXROMVerifySealedFile @0x7d70.
BOOL NXROMVerifySealedFile(NSString *filePath, NSString *domain, NSData *key, NSError **error);

#pragma mark - Device Binding

/// Derives a per-device key from device identifiers.
/// Decompiled from NXROMDeviceKey — binds ROM to specific hardware.
NSData * NXROMDeviceKey(NSString *deviceIdentifier, NSData *masterKey);

/// Full device verification: checks device key + ROM seal + security version.
/// Decompiled from NXROMDeviceVerify @0x81ec.
/// Returns YES if the ROM is authorized for this device at this security version.
BOOL NXROMDeviceVerify(NSData *romSeal, NSString *deviceIdentifier,
                       NSData *masterKey, NSString *romSecurityVersion,
                       NSString *minimumSecurityVersion, NSError **error);

/// Checks that the ROM security version is not older than a previously seen version
/// (anti-downgrade protection).
/// Decompiled from NXROMDeviceCheckRollback @0x8350 / NXROMRollbackCheck @0x91fc.
BOOL NXROMRollbackCheck(NSUInteger currentSecurityVersion, NSUInteger minimumSecurityVersion);

/// Releases a device proof after successful verification (marks ROM as trusted for boot).
/// Decompiled from NXROMDeviceReleaseProof @0x8478.
void NXROMDeviceReleaseProof(void);

#pragma mark - Signing Context

/// Creates a signing context bound to the device key and ROM security version.
/// Decompiled from NXROMDeviceSigningContext @0x8524.
/// This context is used by NXSignMachOAuto to sign binaries with Nyxian entitlements.
@interface NXROMDeviceSigningContext : NSObject
@property (readonly, strong) NSData *deviceKey;
@property (readonly, copy) NSString *securityVersion;
@property (readonly, strong) NSData *publicKey;
- (nullable instancetype)initWithDeviceKey:(NSData *)deviceKey
                           securityVersion:(NSString *)securityVersion
                                publicKey:(NSData *)publicKey;
- (nullable NSData *)signData:(NSData *)data;
- (BOOL)verifyData:(NSData *)data signature:(NSData *)signature;
@end

#pragma mark - Archive Verification

/// Verifies a ROM archive (bootstrap.tar.zst) against an embedded proof.
/// Decompiled from NXROMArchiveProof @0x6d08 and NXROMArchiveProofForFD @0x6740.
BOOL NXROMArchiveProof(NSData *archiveData, NSData *proof, NSData *key, NSError **error);
BOOL NXROMArchiveProofForFD(int fd, NSData *proof, NSData *key, NSError **error);

/// Stages a verified archive: verifies seal → extracts to staging path → renames atomically.
/// Decompiled from NXROMStageVerifiedArchive @0x9f20.
BOOL NXROMStageVerifiedArchive(NSString *archivePath, NSData *proof, NSData *key,
                               NSString *stagingPath, NSString *destinationPath, NSError **error);

#pragma mark - Slot System

/// ROM slot management — allows multiple ROM instances with separate vroots.
/// Decompiled from NXSlotInit @0x5904, NXSlotMain @0x5814,
/// NXSlotCreateWindow @0x5854, NXSlotDisappear @0x58ac.
@interface NXSlotManager : NSObject
+ (instancetype)shared;
- (void)initSlots;
- (NSString *)slotPathForIndex:(NSUInteger)index;
- (void)createWindowForSlot:(NSUInteger)index;
- (void)disappearSlot:(NSUInteger)index;
- (NSUInteger)activeSlotCount;
@end

#pragma mark - ROM Security Domain Constants

/// Domain constants (from decompiled strings in init binary).
static NSString * const NXROMSealDomainBoot         = @"org.emexlabs.switzach.seal.boot";
static NSString * const NXROMSealDomainArchive      = @"org.emexlabs.switzach.seal.archive";
static NSString * const NXROMSealDomainBinary       = @"org.emexlabs.switzach.seal.binary";
static NSString * const NXROMSealDomainManifest     = @"org.emexlabs.switzach.seal.manifest";
static NSString * const NXROMDeviceDomain           = @"org.emexlabs.switzach.device";

NS_ASSUME_NONNULL_END
