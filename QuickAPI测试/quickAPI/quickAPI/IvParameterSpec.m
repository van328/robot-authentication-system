//
//  IvParameterSpec.m
//  quickAPI
//
//  Created by 赵利 on 2018/2/2.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "IvParameterSpec.h"
@interface IvParameterSpec()
@property (nonatomic,strong) NSData *iv;
@end
@implementation IvParameterSpec
-(instancetype)initWithIV:(NSData *)iv{
    return [self initWithIV:iv offset:0 length:(int)iv.length];
}
-(instancetype)initWithIV:(NSData *)iv offset:(int)offset length:(int)len{
    if(iv == nil || iv.length-offset<len || len <0)
        return nil;
    if(self = [super init]){
        NSRange range = NSMakeRange(offset, len);
        self.iv = [iv subdataWithRange:range];
    }
    return self;
}
-(NSData *)getIv{
    return self.iv;
}
@end
