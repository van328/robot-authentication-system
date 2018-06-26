//
//  MAC.m
//  quickAPI
//
//  Created by SecureChip on 2018/2/1.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "MAC.h"
#import <MultiKey/MultiKey.h>
#import "SKF_HMAC.h"
#import "ErrorUtil.h"
@interface MAC ()
@property(nonatomic,strong)id<macInterface> mac;
@property(nonatomic,strong)NSString *mAlgorithm;
@property(nonatomic,assign)BOOL initialized;
@end
@implementation MAC
-(NSString*)getAlgorithm{
    return self.mAlgorithm;
}

+(MAC*)getInstance:(NSString*)algorithm provider:(NSString*)provider{
    if([algorithm isEqualToString:@"HMAC"]&&[provider isEqualToString:@"SC"]){
        id<macInterface> mac = [[SKF_HMAC alloc]init];
        return [[MAC alloc]initWithMac:mac algorithm:algorithm];
    }
    return nil;
}
-(instancetype)initWithMac:(id<macInterface>)mac algorithm:(NSString *)alg{
    if(self=[super init]){
        self.mac = mac;
        self.mAlgorithm =alg;
        self.initialized = NO;
    }
    return self;
}
-(NSData*)doFinal:(NSError**)err{
    if(!self.initialized){
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"doFinal: not initialized err"];
        return nil;
    }
    NSError *error = nil;
    NSData *macData = [self.mac engineDoFinal:err];
    if(error!=nil){
        if (err != nil){
            *err = error;
            NSLog(@"doFinal: doFinal err is %@",(*err).localizedDescription);
        }
        return nil;
    }
    [self.mac engineReset:err];
    if(error!=nil){
        if (err != nil){
            *err = error;
            NSLog(@"doFinal: doFinal err is %@",(*err).localizedDescription);
        }
        return nil;
    }
    return macData;
}
-(NSData*)doFinal:(NSData*)input err:(NSError**)err{
    if(!self.initialized){
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"doFinal: not initialized err"];
        return nil;
    }
    NSError *error = nil;
    [self updateWithData:input err:&error];
    if(error!=nil){
        if (err != nil ){
            *err = error;
            NSLog(@"doFinal: updateWithData err is %@",(*err).localizedDescription);
            return nil;
        }
    }
    NSData *data = [self doFinal:err];
    return data;
    
}
-(void)doFinal:(NSData**)output outoffset:(NSInteger)outoffset err:(NSError**)err{
    if(!self.initialized){
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"doFinal: not initialized err"];
        return;
    }
    NSInteger macLen = [self getMacLength];
    if (output == nil ||*output == nil|| (*output).length - outoffset < macLen){
        NSLog(@"doFinal: cannot store MAC in output buffer");
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:SAR_OBJERR errorMessage:@"doFinal: cannot store MAC in output buffer"];
        return ;
    }
    NSData * mac = [self doFinal:err];
    if (mac == nil){
        NSLog(@"doFinal: mac doFinal err ");
        return;
    }
    memccpy((unsigned char*)(*output).bytes, (unsigned char*)mac.bytes, outoffset, macLen);
}

-(NSInteger)getMacLength{
    return  [self.mac engineGetMacLength];
}
-(void)init:(id<Key>)key err:(NSError**)err{
    if (key == nil||self.mac == nil ){
        NSLog(@"init : key is nil");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_OBJERR errorMessage:@"init : key is nil"];
        return;
    }
    NSError *error = nil;
    [self.mac engineInit:key algorithmparameterSpec:nil err:&error];
    if(error!=nil){
        if(err!=nil)
            *err = error;
        return;
    }
    self.initialized = YES;
}
-(void)init:(id<Key>)key  params:(id<AlgorithmParameterSpec>)params err:(NSError**)err{
    if (key == nil||self.mac == nil||params == nil ){
        NSLog(@"init : key is nil");
        if (err != nil)
            *err = [ErrorUtil geterrorWithCode:SAR_OBJERR errorMessage:@"init : key is nil"];
        return;
    }
    NSError *error = nil;
    [self.mac engineInit:key algorithmparameterSpec:params err:&error];
    if(error!=nil){
        if(err!=nil)
            *err = error;
        return;
    }
    self.initialized = YES;
}
-(void)reset:(NSError **)err{
    [self.mac engineReset:err];
    if (err != nil && *err!=nil)
        NSLog(@"reset: err is %@",(*err).localizedDescription);
    
}
-(void)update:(Byte)input err:(NSError**)err{
    if(!self.initialized){
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:SAR_NOTINITIALIZEERR errorMessage:@"update: "];
        return;
    }else if(input == nil){
        *err = [ErrorUtil geterrorWithCode:SAR_OBJERR errorMessage:@"update: object err"];
        return;
    }
    NSInteger ret = [self.mac engineUpdate:input];
    if(err!=nil)
        *err = (ret == SAR_OK)?nil:[ErrorUtil geterrorWithCode:ret errorMessage:@"update: engineUpdate is not ok"];
}
-(void)updateWithData:(NSData*)input err:(NSError**)err{
    NSInteger ret = SAR_OK;
    if(!self.initialized){
        ret = SAR_NOTINITIALIZEERR;
    }else if(input == nil){
        ret = SAR_OBJERR;
    }
    if(ret != SAR_OK){
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:ret errorMessage:@"updateWithData: ret is not ok"];
        return;
    }
    ret =[self.mac engineUpdate:input offset:0 len:input.length];
    if(err!=nil)
        *err = (ret == SAR_OK)?nil:[ErrorUtil geterrorWithCode:ret errorMessage:@"updateWithData: engineUpdate is not ok"];
}

-(void)update:(NSData*)input offset:(NSInteger)offset len:(NSInteger)len err:(NSError**)err{
    NSInteger ret = SAR_OK;
    if(!self.initialized){
        ret = SAR_NOTINITIALIZEERR;
    }else if(input == nil){
        ret = SAR_OBJERR;
    }else if (offset < 0 || len > (input.length - offset ) || len < 0){
        NSLog(@"update: bad arguments");
        ret = SAR_INVALIDPARAMERR;
    }
    if(ret != SAR_OK){
        if(err!=nil)
            *err = [ErrorUtil geterrorWithCode:ret  errorMessage:@"update: ret is not ok"];
        return;
    }
    ret = [self.mac engineUpdate:input offset:offset len:len];
    if(err!=nil)
        *err = (ret == SAR_OK)?nil:[ErrorUtil geterrorWithCode:ret errorMessage:@"update: engineUpdate is not ok"];
    
}

@end
