/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 ROM security subsystem implementation — rewritten from Ghidra decompilation
 of Switzach v1.0.5 ROM/System/Rom/init.
*/

#import "NXROMSecurity.h"
#include <string.h>

NSString * const NXROMPublicKey = @"NXROMPublicKey";
NSString * const NXROMDeviceKey = @"NXROMDeviceKey";

NSString * const NXROMSealDomainBoot         = @"org.emexlabs.switzach.seal.boot";
NSString * const NXROMSealDomainArchive      = @"org.emexlabs.switzach.seal.archive";
NSString * const NXROMSealDomainBinary       = @"org.emexlabs.switzach.seal.binary";
NSString * const NXROMSealDomainManifest     = @"org.emexlabs.switzach.seal.manifest";
NSString * const NXROMDeviceDomain           = @"org.emexlabs.switzach.device";

#pragma mark - Seal Verification

BOOL NXROMVerifySeal(NSData *sealBlob, NSString *expectedDomain, NSData *verificationKey) {
    if (sealBlob.length < 40) return NO; // minimum: 8 domain_tag + 32 mac

    // Layout: domain_tag(8) || mac(32) || payload(N)
    NSData *domainTag = [sealBlob subdataWithRange:NSMakeRange(0, 8)];
    NSData *embeddedMAC = [sealBlob subdataWithRange:NSMakeRange(8, 32)];
    NSData *payload = [sealBlob subdataWithRange:NSMakeRange(40, sealBlob.length - 40)];

    // Check domain tag matches
    const char *dom = [expectedDomain UTF8String];
    if (sealBlob.length >= 8 && memcmp(domainTag.bytes, dom, MIN(8, strlen(dom))) != 0) {
        return NO;
    }

    // Compute expected MAC over payload with domain separation
    NSData *expectedMAC = NXROMSealMAC(expectedDomain, verificationKey, payload);
    return [embeddedMAC isEqualToData:expectedMAC];
}

BOOL NXROMVerifySealedFile(NSString *filePath, NSString *domain, NSData *key, NSError **error) {
    NSData *fileData = [NSData dataWithContentsOfFile:filePath];
    if (!fileData || fileData.length < 40) {
        if (error) *error = [NSError errorWithDomain:@"NXROMSecurity" code:1
            userInfo:@{NSLocalizedDescriptionKey: @"File too small or unreadable"}];
        return NO;
    }

    // The seal is prepended to the file content
    NSData *sealBlob = [fileData subdataWithRange:NSMakeRange(0, 40)];
    NSData *filePayload = [fileData subdataWithRange:NSMakeRange(40, fileData.length - 40)];

    NSData *embeddedMAC = [sealBlob subdataWithRange:NSMakeRange(8, 32)];
    NSData *expectedMAC = NXROMSealMAC(domain, key, filePayload);

    if (![embeddedMAC isEqualToData:expectedMAC]) {
        if (error) *error = [NSError errorWithDomain:@"NXROMSecurity" code:2
            userInfo:@{NSLocalizedDescriptionKey: @"Seal MAC mismatch"}];
        return NO;
    }
    return YES;
}

#pragma mark - Device Binding

NSData * NXROMDeviceKey(NSString *deviceIdentifier, NSData *masterKey) {
    // Derive per-device key: HMAC-SHA256(masterKey, deviceIdentifier)
    const char *id = [deviceIdentifier UTF8String];
    unsigned char derived[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, masterKey.bytes, masterKey.length,
           id, strlen(id), derived);
    return [NSData dataWithBytes:derived length:CC_SHA256_DIGEST_LENGTH];
}

BOOL NXROMDeviceVerify(NSData *romSeal, NSString *deviceIdentifier,
                       NSData *masterKey, NSString *romSecurityVersion,
                       NSString *minimumSecurityVersion, NSError **error) {
    // Step 1: derive device key
    NSData *devKey = NXROMDeviceKey(deviceIdentifier, masterKey);

    // Step 2: verify ROM seal against device key
    if (!NXROMVerifySeal(romSeal, NXROMDeviceDomain, devKey)) {
        if (error) *error = [NSError errorWithDomain:@"NXROMSecurity" code:3
            userInfo:@{NSLocalizedDescriptionKey: @"ROM seal verification failed for this device"}];
        return NO;
    }

    // Step 3: check rollback (anti-downgrade)
    NSUInteger current = NXROMParseSecurityVersion(romSecurityVersion);
    NSUInteger minimum = NXROMParseSecurityVersion(minimumSecurityVersion);
    if (!NXROMRollbackCheck(current, minimum)) {
        if (error) *error = [NSError errorWithDomain:@"NXROMSecurity" code:4
            userInfo:@{NSLocalizedDescriptionKey:
                [NSString stringWithFormat:@"Security version rollback: current=%lu minimum=%lu",
                 (unsigned long)current, (unsigned long)minimum]}];
        return NO;
    }

    return YES;
}

BOOL NXROMRollbackCheck(NSUInteger currentSecurityVersion, NSUInteger minimumSecurityVersion) {
    return currentSecurityVersion >= minimumSecurityVersion;
}

void NXROMDeviceReleaseProof(void) {
    // In the decompiled binary this likely clears an in-memory proof flag
    // or signals to the boot chain that verification is complete.
    // Implementation: no-op for our integration (the proof lifecycle is
    // managed by Nyxian's PEUserspaceManager boot sequence).
}

#pragma mark - Signing Context

@implementation NXROMDeviceSigningContext

- (nullable instancetype)initWithDeviceKey:(NSData *)deviceKey
                           securityVersion:(NSString *)securityVersion
                                publicKey:(NSData *)publicKey {
    if (!deviceKey || !securityVersion || !publicKey) return nil;
    self = [super init];
    if (self) {
        _deviceKey = [deviceKey copy];
        _securityVersion = [securityVersion copy];
        _publicKey = [publicKey copy];
    }
    return self;
}

- (nullable NSData *)signData:(NSData *)data {
    // HMAC-SHA256 signing using the device key with binary domain
    return NXROMSealMAC(NXROMSealDomainBinary, self.deviceKey, data);
}

- (BOOL)verifyData:(NSData *)data signature:(NSData *)signature {
    NSData *expected = [self signData:data];
    return [expected isEqualToData:signature];
}

@end

#pragma mark - Archive Verification

BOOL NXROMArchiveProof(NSData *archiveData, NSData *proof, NSData *key, NSError **error) {
    // proof format: {mac(32)} — MAC over the entire archive
    if (proof.length < 32) {
        if (error) *error = [NSError errorWithDomain:@"NXROMSecurity" code:5
            userInfo:@{NSLocalizedDescriptionKey: @"Proof too short"}];
        return NO;
    }
    NSData *embeddedMAC = [proof subdataWithRange:NSMakeRange(0, 32)];
    NSData *expectedMAC = NXROMSealMAC(NXROMSealDomainArchive, key, archiveData);
    if (![embeddedMAC isEqualToData:expectedMAC]) {
        if (error) *error = [NSError errorWithDomain:@"NXROMSecurity" code:6
            userInfo:@{NSLocalizedDescriptionKey: @"Archive proof MAC mismatch"}];
        return NO;
    }
    return YES;
}

BOOL NXROMArchiveProofForFD(int fd, NSData *proof, NSData *key, NSError **error) {
    // Read the entire file from fd
    NSData *archiveData = [NSData dataWithContentsOfFile:
        [NSString stringWithFormat:@"/proc/self/fd/%d", fd]];
    if (!archiveData) {
        if (error) *error = [NSError errorWithDomain:@"NXROMSecurity" code:7
            userInfo:@{NSLocalizedDescriptionKey: @"Cannot read from fd"}];
        return NO;
    }
    return NXROMArchiveProof(archiveData, proof, key, error);
}

BOOL NXROMStageVerifiedArchive(NSString *archivePath, NSData *proof, NSData *key,
                               NSString *stagingPath, NSString *destinationPath, NSError **error) {
    // 1. Verify the archive
    NSData *archiveData = [NSData dataWithContentsOfFile:archivePath];
    if (!archiveData) {
        if (error) *error = [NSError errorWithDomain:@"NXROMSecurity" code:8
            userInfo:@{NSLocalizedDescriptionKey: @"Cannot read archive"}];
        return NO;
    }
    if (!NXROMArchiveProof(archiveData, proof, key, error)) return NO;

    // 2. Copy to staging path
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm copyItemAtPath:archivePath toPath:stagingPath error:error]) return NO;

    // 3. Create destination directory
    [fm createDirectoryAtPath:destinationPath
        withIntermediateDirectories:YES attributes:nil error:nil];

    // 4. Extract archive (zstd decompress + untar) using NSFileCoordinator
    // The actual extraction is delegated to the bootstrap system
    // (NXManageBootstrap handles this in the ROM flow)

    return YES;
}

#pragma mark - Slot Manager

@implementation NXSlotManager {
    NSMutableDictionary<NSNumber *, NSString *> *_slots;
}

+ (instancetype)shared {
    static NXSlotManager *shared;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[NXSlotManager alloc] init];
    });
    return shared;
}

- (instancetype)init {
    if ((self = [super init])) {
        _slots = [NSMutableDictionary dictionary];
    }
    return self;
}

- (void)initSlots {
    emit_slot_log("slots initialized");
}

- (NSString *)slotPathForIndex:(NSUInteger)index {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:
        [NSString stringWithFormat:@"Slots/A/%lu", (unsigned long)index]];
    _slots[@(index)] = path;
    return path;
}

- (void)createWindowForSlot:(NSUInteger)index {
    // In the decompiled binary this creates a UI window for the slot's SpringBoard.
    // For our integration this is a no-op (we don't need per-slot UI).
}

- (void)disappearSlot:(NSUInteger)index {
    [_slots removeObjectForKey:@(index)];
}

- (NSUInteger)activeSlotCount {
    return _slots.count;
}

@end

// Helper for slot logging (from decompiled binary's klog_log_internal pattern)
static void emit_slot_log(const char *msg) {
    NSLog(@"[NXSlotManager] %s", msg);
}
