//
//  KeyPairGenerator.h
//  quickAPI
//
//  Created by SecureChip on 2018/2/26.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "KeyPairGeneratorSpi.h"
@interface KeyPairGenerator : NSObject<KeyPairGeneratorSpi>
+(KeyPairGenerator*)getInstance:(NSString*)algorithm provider:(NSString*)provider;
- (void)initialize:(id<AlgorithmParameterSpec>)params err:(NSError *__autoreleasing *)err;
@end
