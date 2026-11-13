#import "NXPhaseStub.h"

@implementation NXPhaseEngine
- (nullable instancetype)initWithProject:(id)project error:(NSError **)error {
    return [super init];
}
@end

@implementation NXPhaseRunner
- (nullable instancetype)initWithEngine:(NXPhaseEngine *)engine error:(NSError **)error {
    return [super init];
}
- (BOOL)runPhase:(id)phase error:(NSError **)error {
    return NO;
}
@end
