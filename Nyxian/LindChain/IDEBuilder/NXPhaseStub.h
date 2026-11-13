// Stub replacements for MDK-dependent classes
#import <Foundation/Foundation.h>

@class MDKPhase;
@class MDKJob;

@interface NXPhaseEngine : NSObject
- (nullable instancetype)initWithProject:(id)project error:(NSError **)error;
@end

@interface NXPhaseRunner : NSObject
- (nullable instancetype)initWithEngine:(NXPhaseEngine *)engine error:(NSError **)error;
- (BOOL)runPhase:(id)phase error:(NSError **)error;
@end
