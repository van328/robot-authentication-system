//
//  ECCKeyPairBlob.h
//  SecurecoreMoreKey
//
//  Created by SecureChip on 2018/1/23.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ECCPublicKeyBlob.h"
@interface ECCKeyPairBlob : NSObject
@property(nonatomic,strong,readonly)NSData* priKey;
@property(nonatomic,strong,readonly)ECCPublicKeyBlob *mECCPublicKeyBlob;
-(void)setPriKey:(NSData *)priKey;
-(void)setMECCPublicKeyBlob:(ECCPublicKeyBlob *)mECCPublicKeyBlob;
@end
