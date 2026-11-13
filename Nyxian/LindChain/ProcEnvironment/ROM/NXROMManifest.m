/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 NXROMManifest.m — ROM manifest parser implementation.
*/

#import "NXROMManifest.h"

NSString * const NXRomManifestVersion = @"NXRomManifestVersion";
NSString * const NXRomIdentifier = @"NXRomIdentifier";
NSString * const NXRomName = @"NXRomName";
NSString * const NXRomVersion = @"NXRomVersion";
NSString * const NXRomSecurityVersion = @"NXRomSecurityVersion";
NSString * const NXRomMinimumNyxianVersion = @"NXRomMinimumNyxianVersion";
NSString * const NXRomDefaultFilePermission = @"NXRomDefaultFilePermission";
NSString * const NXRomDefaultDirectoryPermission = @"NXRomDefaultDirectoryPermission";
NSString * const NXRomPaths = @"NXRomPaths";
NSString * const NXPath = @"NXPath";
NSString * const NXPermission = @"NXPermission";
NSString * const NXRequiresCodeSigning = @"NXRequiresCodeSigning";

@implementation NXROMPathEntry
@end

@implementation NXROMManifest

- (nullable instancetype)initWithPlistData:(NSData *)plistData error:(NSError **)error {
    NSError *parseError = nil;
    id plist = [NSPropertyListSerialization propertyListWithData:plistData
        options:NSPropertyListImmutable format:nil error:&parseError];
    if (!plist || ![plist isKindOfClass:[NSDictionary class]]) {
        if (error) *error = parseError ?: [NSError errorWithDomain:@"NXROM" code:1
            userInfo:@{NSLocalizedDescriptionKey: @"Invalid plist"}];
        return nil;
    }
    return [self initWithDictionary:(NSDictionary *)plist error:error];
}

- (nullable instancetype)initWithPlistPath:(NSString *)path error:(NSError **)error {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) {
        if (error) *error = [NSError errorWithDomain:@"NXROM" code:2
            userInfo:@{NSLocalizedDescriptionKey: @"Cannot read manifest file"}];
        return nil;
    }
    return [self initWithPlistData:data error:error];
}

- (nullable instancetype)initWithDictionary:(NSDictionary *)dict error:(NSError **)error {
    self = [super init];
    if (!self) return nil;

    // Required fields
    _romIdentifier = dict[NXRomIdentifier];
    _romName = dict[NXRomName];
    _romVersion = dict[NXRomVersion];
    _minimumNyxianVersion = dict[NXRomMinimumNyxianVersion];

    if (!_romIdentifier || !_romVersion || !_minimumNyxianVersion) {
        if (error) *error = [NSError errorWithDomain:@"NXROM" code:3
            userInfo:@{NSLocalizedDescriptionKey: @"Missing required manifest keys"}];
        return nil;
    }

    _securityVersion = [dict[NXRomSecurityVersion] unsignedIntegerValue] ?: 0;
    _defaultFilePermission = [dict[NXRomDefaultFilePermission] unsignedIntegerValue] ?: 420;
    _defaultDirectoryPermission = [dict[NXRomDefaultDirectoryPermission] unsignedIntegerValue] ?: 493;

    // Parse path entries
    NSMutableArray<NXROMPathEntry *> *entries = [NSMutableArray array];
    NSArray *paths = dict[NXRomPaths];
    if ([paths isKindOfClass:[NSArray class]]) {
        for (NSDictionary *pathDict in paths) {
            if (![pathDict isKindOfClass:[NSDictionary class]]) continue;
            id nxPath = pathDict[NXPath];
            NSArray<NSString *> *pathArray = nil;
            if ([nxPath isKindOfClass:[NSString class]]) {
                pathArray = @[nxPath];
            } else if ([nxPath isKindOfClass:[NSArray class]]) {
                pathArray = nxPath;
            }
            NSUInteger perm = [pathDict[NXPermission] unsignedIntegerValue] ?: 420;
            BOOL requiresCS = [pathDict[NXRequiresCodeSigning] boolValue];
            for (NSString *p in pathArray) {
                NXROMPathEntry *entry = [[NXROMPathEntry alloc] init];
                // We use private setters here or a custom init
                [entry setValue:p forKey:@"path"];
                [entry setValue:@(perm) forKey:@"permission"];
                [entry setValue:@(requiresCS) forKey:@"requiresCodeSigning"];
                [entries addObject:entry];
            }
        }
    }
    _pathEntries = [entries copy];

    return self;
}

- (BOOL)isCompatibleWithNyxianVersion:(NSString *)nyxianVersion {
    if (!nyxianVersion || !_minimumNyxianVersion) return NO;

    // Simple semantic version comparison
    NSArray *run = [nyxianVersion componentsSeparatedByString:@"."];
    NSArray *min = [_minimumNyxianVersion componentsSeparatedByString:@"."];

    for (NSUInteger i = 0; i < MAX(run.count, min.count); i++) {
        NSInteger rv = i < run.count ? [run[i] integerValue] : 0;
        NSInteger mv = i < min.count ? [min[i] integerValue] : 0;
        if (rv > mv) return YES;
        if (rv < mv) return NO;
    }
    return YES; // equal
}

- (NSArray<NSString *> *)pathsRequiringCodeSigning {
    return [self.pathEntries
        filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"requiresCodeSigning == YES"]]
        valueForKey:@"path"];
}

- (NSUInteger)permissionForPath:(NSString *)path {
    for (NXROMPathEntry *entry in self.pathEntries) {
        if ([entry.path isEqualToString:path]) return entry.permission;
    }
    return self.defaultFilePermission;
}

@end
