//
//  KeyPair.h
//  quickAPI
//
//  Created by SecureChip on 2018/2/26.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PublicKey.h"
#import "PrivateKey.h"
@interface KeyPair : NSObject
-(instancetype)init:(id<PublicKey>)publicKey privateKey:(id<PrivateKey>)privateKey;
-(id<PublicKey>)getPublic;
-(id<PrivateKey>)getPrivate;
@end
