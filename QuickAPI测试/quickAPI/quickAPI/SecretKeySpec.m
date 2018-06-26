//
//  SecretKeySpec.m
//  quickAPI
//
//  Created by 赵利 on 2018/2/2.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SecretKeySpec.h"
@interface SecretKeySpec()
@property (nonatomic,strong) NSData *key;
@property (nonatomic,copy) NSString *algorithm;
@end
@implementation SecretKeySpec
-(instancetype)initWithKey:(NSData *)key algorithm:(NSString *)alg{
    if(self = [super init]){
        if(key == nil || alg == nil|| key.length == 0)
            return nil;
        self.key = key;
        self.algorithm = alg;
    }
    return self;
}
-(instancetype)initWithKey:(NSData *)key offset:(int)offset length:(int)len algorithm:(NSString *)alg{
    if(key == nil || key.length-offset<len || len <0 || key.length == 0)
        return nil;
    if(self = [super init]){
        NSRange range = NSMakeRange(offset, len);
        self.key = [key subdataWithRange:range];
        self.algorithm = alg;
    }
    return self;
}
- (NSString *)getAlgorithm {
    return self.algorithm;
}

- (NSData *)getEncoded {
    return self.key;
}

- (NSString *)getFormat {
    return @"RAW";
}

@end
