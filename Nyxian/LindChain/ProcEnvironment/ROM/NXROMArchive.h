/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 NXROMArchive.h — ROM archive verification, staging and deployment.
 Handles bootstrap.tar.zst integrity checking and atomic staging.
*/

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Verifies archive integrity via HMAC proof, then stages it atomically.
/// Proof format: {HMAC-SHA256(archive_data)} (32 bytes).
/// Flow: verify → copy to staging → extract → atomic rename to destination.
@interface NXROMArchive : NSObject

/// Stage a verified ROM archive for deployment.
/// @param archivePath Path to the bootstrap.tar.zst file.
/// @param proof HMAC-SHA256 proof (32 bytes) over the archive data.
/// @param key The device key for MAC verification.
/// @param stagingPath Where to temporarily place the verified archive.
/// @param destinationPath Where to atomically move the archive after staging.
/// @param error On failure, contains the reason.
/// @return YES if verification succeeded and archive was staged.
+ (BOOL)stageVerifiedArchive:(NSString *)archivePath
                       proof:(NSData *)proof
                         key:(NSData *)key
                 stagingPath:(NSString *)stagingPath
             destinationPath:(NSString *)destinationPath
                       error:(NSError **)error;

/// Verify archive integrity (HMAC-SHA256 proof check only, no staging).
+ (BOOL)verifyArchive:(NSData *)archiveData
                proof:(NSData *)proof
                  key:(NSData *)key
                error:(NSError **)error;

/// Compute the proof for an archive (for signing during ROM creation).
+ (nullable NSData *)computeProof:(NSData *)archiveData key:(NSData *)key;

/// Extract a tar.zst archive to a destination directory.
/// Uses libarchive (available on iOS via system frameworks).
+ (BOOL)extractTarZst:(NSString *)archivePath toDirectory:(NSString *)destDir error:(NSError **)error;

/// Compute CDHash of a Mach-O binary (from the decompiled _CDHashOfMachO).
+ (nullable NSData *)cdHashOfMachO:(NSString *)machOPath error:(NSError **)error;

/// Verify CDHash of a Mach-O matches an expected value.
+ (BOOL)verifyMachOCDHash:(NSString *)machOPath expectedCDHash:(NSData *)expectedCDHash error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
