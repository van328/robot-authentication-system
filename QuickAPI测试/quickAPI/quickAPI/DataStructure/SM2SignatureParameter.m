//
//  SM2SignatureParameter.m
//  quickAPI
//
//  Created by 赵利 on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SM2SignatureParameter.h"
@interface SM2SignatureParameter()
@property (nonatomic,copy) NSString *SignatureKeyPairAlias;
@end
@implementation SM2SignatureParameter
-(instancetype)initWithAlias:(NSString *)signatureKeyPairAlias isGenerate:(BOOL)forGenerate{
    if(self = [super init]){
        self.SignatureKeyPairAlias = signatureKeyPairAlias;
    }
    return self;
}
-(NSString *)getSignatureKeyPairAlias{
    return self.SignatureKeyPairAlias;
}
-(void)setSignatureKeyPairAlias:(NSString *)signatureKeyPairAlias{
    _SignatureKeyPairAlias = signatureKeyPairAlias;
}
@end
