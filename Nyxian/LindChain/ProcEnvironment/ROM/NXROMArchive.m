/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 NXROMArchive.m — ROM archive verification and staging implementation.
*/

#import "NXROMArchive.h"
#import "NXROMSecurity.h"
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>

@implementation NXROMArchive

+ (BOOL)verifyArchive:(NSData *)archiveData proof:(NSData *)proof key:(NSData *)key error:(NSError **)error {
    if (!archiveData || !proof || !key || proof.length < 32) {
        if (error) *error = [NSError errorWithDomain:@"NXROMArchive" code:1
            userInfo:@{NSLocalizedDescriptionKey: @"Invalid arguments (need archive, proof>=32B, key)"}];
        return NO;
    }
    return NXROMArchiveProof(archiveData, proof, key, error);
}

+ (nullable NSData *)computeProof:(NSData *)archiveData key:(NSData *)key {
    if (!archiveData || !key) return nil;
    return NXROMSealMAC(NXROMSealDomainArchive, key, archiveData);
}

+ (BOOL)stageVerifiedArchive:(NSString *)archivePath
                       proof:(NSData *)proof
                         key:(NSData *)key
                 stagingPath:(NSString *)stagingPath
             destinationPath:(NSString *)destinationPath
                       error:(NSError **)error {

    NSFileManager *fm = [NSFileManager defaultManager];

    // 1. Read archive
    NSData *archiveData = [NSData dataWithContentsOfFile:archivePath];
    if (!archiveData) {
        if (error) *error = [NSError errorWithDomain:@"NXROMArchive" code:2
            userInfo:@{NSLocalizedDescriptionKey: @"Cannot read archive file"}];
        return NO;
    }

    // 2. Verify integrity
    if (![self verifyArchive:archiveData proof:proof key:key error:error]) return NO;

    // 3. Create staging directory
    NSString *stagingDir = [stagingPath stringByDeletingLastPathComponent];
    if (![fm createDirectoryAtPath:stagingDir withIntermediateDirectories:YES
                            attributes:nil error:error]) return NO;

    // 4. Copy to staging
    if ([fm fileExistsAtPath:stagingPath]) [fm removeItemAtPath:stagingPath error:nil];
    if (![fm copyItemAtPath:archivePath toPath:stagingPath error:error]) return NO;

    // 5. Create destination parent
    NSString *destDir = [destinationPath stringByDeletingLastPathComponent];
    if (![fm createDirectoryAtPath:destDir withIntermediateDirectories:YES
                            attributes:nil error:error]) return NO;

    // 6. Atomic move staging → destination
    if ([fm fileExistsAtPath:destinationPath]) [fm removeItemAtPath:destinationPath error:nil];
    if (![fm moveItemAtPath:stagingPath toPath:destinationPath error:error]) return NO;

    return YES;
}

+ (BOOL)extractTarZst:(NSString *)archivePath toDirectory:(NSString *)destDir error:(NSError **)error {
    // libarchive is available via system libraries; use popen with tar if available
    // On iOS, use the built-in tar via MobileDevelopmentKit or shell through PEProcessManager.
    // Simplification: use NSTask if available (iOS 16+ has no NSTask for sandboxed apps;
    // but inside Nyxian ROM environment we spawn via PEProcessManager).
    // Fallback: return NO with clear error.
    if (error) *error = [NSError errorWithDomain:@"NXROMArchive" code:3
        userInfo:@{NSLocalizedDescriptionKey:
            @"extractTarZst must be called via PEProcessManager (spawn /usr/bin/tar) inside ROM"}];
    return NO;
}

+ (nullable NSData *)cdHashOfMachO:(NSString *)machOPath error:(NSError **)error {
    NSData *data = [NSData dataWithContentsOfFile:machOPath];
    if (!data) {
        if (error) *error = [NSError errorWithDomain:@"NXROMArchive" code:4
            userInfo:@{NSLocalizedDescriptionKey: @"Cannot read Mach-O file"}];
        return nil;
    }

    // CDHash = SHA256 of the code directory blob
    // Parse LC_CODE_SIGNATURE (cmd 0x1d) to find the CS_SuperBlob, then extract CD blob (type 0)
    // Simplified: search for the code signature and hash it
    if (data.length < 32) {
        if (error) *error = [NSError errorWithDomain:@"NXROMArchive" code:5
            userInfo:@{NSLocalizedDescriptionKey: @"File too small"}];
        return nil;
    }

    // Parse Mach-O header for LC_CODE_SIGNATURE
    uint32_t magic = *(uint32_t *)data.bytes;
    if (magic != 0xfeedfacf && magic != 0xcffaedfe) {
        if (error) *error = [NSError errorWithDomain:@"NXROMArchive" code:6
            userInfo:@{NSLocalizedDescriptionKey: @"Not a 64-bit Mach-O"}];
        return nil;
    }

    uint32_t ncmds = *(uint32_t *)((uint8_t *)data.bytes + 16);
    uint32_t off = 32;
    uint32_t sigoff = 0, sigsize = 0;
    for (uint32_t i = 0; i < ncmds && off + 8 <= data.length; i++) {
        uint32_t cmd = *(uint32_t *)((uint8_t *)data.bytes + off);
        uint32_t csz = *(uint32_t *)((uint8_t *)data.bytes + off + 4);
        if ((cmd & 0x7fffffff) == 0x1d) {  // LC_CODE_SIGNATURE
            sigoff = *(uint32_t *)((uint8_t *)data.bytes + off + 8);
            sigsize = *(uint32_t *)((uint8_t *)data.bytes + off + 12);
            break;
        }
        off += csz;
    }

    if (sigoff == 0 || sigoff + sigsize > data.length) {
        if (error) *error = [NSError errorWithDomain:@"NXROMArchive" code:7
            userInfo:@{NSLocalizedDescriptionKey: @"No code signature found"}];
        return nil;
    }

    // SuperBlob: magic(4) length(4) count(4) then entries
    NSData *sigBlob = [data subdataWithRange:NSMakeRange(sigoff, sigsize)];
    if (sigBlob.length < 12) return nil;

    // Find CodeDirectory blob (type 0)
    uint32_t count = ntohl(*(uint32_t *)((uint8_t *)sigBlob.bytes + 8));
    for (uint32_t i = 0; i < count; i++) {
        uint32_t eoff = 12 + i * 8;
        if (eoff + 8 > sigBlob.length) break;
        uint32_t btype = ntohl(*(uint32_t *)((uint8_t *)sigBlob.bytes + eoff));
        uint32_t boff = ntohl(*(uint32_t *)((uint8_t *)sigBlob.bytes + eoff + 4));
        if (btype == 0 && boff + 8 <= sigBlob.length) {  // CodeDirectory
            uint32_t cdlen = ntohl(*(uint32_t *)((uint8_t *)sigBlob.bytes + boff + 4));
            if (boff + cdlen <= sigBlob.length) {
                NSData *cd = [sigBlob subdataWithRange:NSMakeRange(boff, cdlen)];
                unsigned char hash[CC_SHA256_DIGEST_LENGTH];
                CC_SHA256(cd.bytes, (CC_LONG)cd.length, hash);
                return [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
            }
        }
    }

    if (error) *error = [NSError errorWithDomain:@"NXROMArchive" code:8
        userInfo:@{NSLocalizedDescriptionKey: @"CodeDirectory blob not found"}];
    return nil;
}

+ (BOOL)verifyMachOCDHash:(NSString *)machOPath expectedCDHash:(NSData *)expectedCDHash error:(NSError **)error {
    NSData *actual = [self cdHashOfMachO:machOPath error:error];
    if (!actual) return NO;
    return [actual isEqualToData:expectedCDHash];
}

@end
