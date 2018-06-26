//
//  SM2KeyPairParameter.m
//  quickAPI
//
//  Created by 赵利 on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SM2KeyPairParameter.h"
@interface SM2KeyPairParameter()
@property (nonatomic,copy) NSString *KeyPairAlias;
@end
@implementation SM2KeyPairParameter
-(instancetype)initWithAlias:(NSString *)KeyPairAlias{
    if(self = [super init]){
        self.KeyPairAlias = KeyPairAlias;
    }
    return self;
}
-(NSString *)getKeyPairAlias{
    return self.KeyPairAlias;
}
-(void)setKeyPairAlias:(NSString *)KeyPairAlias{
    _KeyPairAlias = KeyPairAlias;
}
@end
