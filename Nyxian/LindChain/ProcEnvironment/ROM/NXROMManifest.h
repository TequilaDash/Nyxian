/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 NXROMManifest.h — ROM manifest.plist parser and validator.
 Rewritten from Ghidra decompilation of Switzach v1.0.5 init (4312 functions).

 The manifest defines the entire ROM package: paths, permissions, code signing
 requirements, and the minimum Nyxian version. Without this the ROM cannot be
 staged or verified.
*/

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// ROM manifest root keys (from Switzach v1.0.5 manifest.plist)
extern NSString * const NXRomManifestVersion;
extern NSString * const NXRomIdentifier;
extern NSString * const NXRomName;
extern NSString * const NXRomVersion;
extern NSString * const NXRomSecurityVersion;
extern NSString * const NXRomMinimumNyxianVersion;
extern NSString * const NXRomDefaultFilePermission;
extern NSString * const NXRomDefaultDirectoryPermission;
extern NSString * const NXRomPaths;

/// Per-path entry keys
extern NSString * const NXPath;
extern NSString * const NXPermission;
extern NSString * const NXRequiresCodeSigning;

/// Represents a single file path entry in the ROM manifest
@interface NXROMPathEntry : NSObject
@property (readonly, copy) NSString *path;
@property (readonly) NSUInteger permission;
@property (readonly) BOOL requiresCodeSigning;
@end

/// Parses and validates a ROM manifest.plist
@interface NXROMManifest : NSObject

@property (readonly, copy) NSString *romIdentifier;
@property (readonly, copy) NSString *romName;
@property (readonly, copy) NSString *romVersion;
@property (readonly) NSUInteger securityVersion;
@property (readonly, copy) NSString *minimumNyxianVersion;
@property (readonly) NSUInteger defaultFilePermission;
@property (readonly) NSUInteger defaultDirectoryPermission;
@property (readonly, strong) NSArray<NXROMPathEntry *> *pathEntries;

/// Parse manifest from plist data. Returns nil if invalid or missing required keys.
- (nullable instancetype)initWithPlistData:(NSData *)plistData error:(NSError **)error;

/// Parse manifest from file path.
- (nullable instancetype)initWithPlistPath:(NSString *)path error:(NSError **)error;

/// Check if this manifest's minimum Nyxian version is compatible with the running Nyxian.
- (BOOL)isCompatibleWithNyxianVersion:(NSString *)nyxianVersion;

/// Get all paths that require code signing.
- (NSArray<NSString *> *)pathsRequiringCodeSigning;

/// Get the permission for a specific path (falls back to default).
- (NSUInteger)permissionForPath:(NSString *)path;

@end

NS_ASSUME_NONNULL_END
