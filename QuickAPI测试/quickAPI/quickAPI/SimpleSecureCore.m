//
//  SimpleSecureCore.m
//  quickAPI
//
//  Created by SecureChip on 2018/1/30.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import "SimpleSecureCore.h"
#import "defines.h"
#import "StringUtils.h"
@interface SimpleSecureCore()
@property(strong,nonatomic)SecureCoreDevice* device;
@property(strong,nonatomic)SCApplication* app;
@property(strong,nonatomic)SCContainer* LocalCon;
@property(strong,nonatomic)SCContainer* CoopCon;
@property(strong,nonatomic)NSString* appID;
@property(strong,nonatomic)NSString* appSecret;
@property(strong,nonatomic)ServerInfo* addr;
//签名公钥结构
@property(nonatomic,strong)ECCPublicKeyBlob *signPubkey;
//导出的公钥结构
@property(nonatomic,strong)NSData *pubkeyBytes;
//加密的公钥
@property(nonatomic,copy)NSString *encryptPubkeyString;
//加密的私钥
@property(nonatomic,copy)NSString *encryptPrikeyString;
@end
@implementation SimpleSecureCore
//static SimpleSecureCore *instance = nil;
+(instancetype)getinstance{
    static SimpleSecureCore *my = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
            my = [[self alloc]init];
            my.addr =  [[ServerInfo alloc]init];
            my.device = [my getDefaultDevice];
            my.app = [my getDefaultApplication];
            my.LocalCon = [my getDefaultContainer];
            my.CoopCon = [my getDefaultRemoteContainer];
    });
    return my;
}
//+ (instancetype)allocWithZone:(struct _NSZone *)zone
//{
//    static dispatch_once_t onceToken;
//    dispatch_once(&onceToken, ^{
//        instance = [super allocWithZone:zone];
//    });
//    return instance;
//}

-(void)init:(NSString*)appID appSecret:(NSString*)appSecret IP:(NSString*)IP port:(NSInteger)port{
    self.appID = appID;
    self.appSecret = appSecret;
    self.addr.ip = IP;
    self.addr.port = (int)port;
}

-(NSString*)getAppID{
    return self.appID;
}

-(NSString*)getAppSecret{
    return self.appSecret;
}

-(ServerInfo*)getAddr{
    return self.addr;
}
-(NSString *)getDefaultPIN{
    return defaultPin;
}
-(ECCPublicKeyBlob*)getRandPublicKey{
    ECCPublicKeyBlob *publicKeyBlob = [[ECCPublicKeyBlob alloc]init];
    NSData * pre =  [Tool convertHexStrToData:@"04"];
    NSData * pubkeytail = [self getRand:true maxLen:64];
    NSMutableData * pubkey =[NSMutableData data];
    [pubkey appendData:pre];
    [pubkey appendData:pubkeytail];
    [publicKeyBlob readFromByteArray:pubkey];
    return publicKeyBlob;
}

-(ECCSignatureBlob*)getRandSignature{
    ECCSignatureBlob *signatureBlob  = [[ECCSignatureBlob alloc]init];
    NSData * sign = [self getRand:true maxLen:64];
    NSData *r = [sign subdataWithRange:NSMakeRange(0, 32)];
    NSData *s = [sign subdataWithRange:NSMakeRange(32, 32)];
    [signatureBlob setR:r];
    [signatureBlob setS:s];
    return signatureBlob;
}
-(BlockCipherParam*)getRandBlockCipherParam{
    BlockCipherParam *blockCipherParam = [[BlockCipherParam alloc]init];
    [blockCipherParam setiv:[self getRand:true maxLen:16]];
    [blockCipherParam setPaddingType:(arc4random()%2)];
    [blockCipherParam setFeedBitLen:((long)arc4random()%2)];
    return blockCipherParam;
}
//-(long)getRandLong;

-(NSData*)getRand:(BOOL)fixedLength maxLen:(NSInteger)maxLen{
    if(!fixedLength){
        maxLen = arc4random()%maxLen+1;
    }
    srand((unsigned int)time(0));
    unsigned char arr[maxLen];
    for (int index = 0; index < maxLen; index++)
        arr[index] = (unsigned char) rand();
    NSData *data=[NSData dataWithBytes:arr length:maxLen];
    return data;
}

-(ECCPublicKeyBlob *)getPublicKey:(bool)signFlag{
    if(self.LocalCon==nil)
        self.LocalCon=[self getDefaultContainer];
    NSError *err=nil;
    NSData *pubdata=[self.LocalCon SKF_ExportPublicKey:signFlag err:&err];
    if(err!=nil){
        NSLog(@"MyUtils:SKF_ExportPublicKey: rs=%@",err.localizedDescription);
        return nil;
    }
    ECCPublicKeyBlob * pub=[[ECCPublicKeyBlob alloc]init];
    [pub readFromByteArray:pubdata];
    return pub;
}
-(SecureCoreDevice*)getDefaultDevice{
    self.device = [SecureCoreDevice sharedCoreDevice];
    ResultCode rs = [self.device Initialize];
    if (rs != SAR_OK) {
        NSLog(@"SimpleSecureCore: getDefaultDevice fail");
        return nil;
    }
//    ECCKeyPairBlob* ecckeypair = [[ECCKeyPairBlob alloc]init];
//    ECCPublicKeyBlob *pub = [[ECCPublicKeyBlob alloc]init];
//    NSData *p = [Tool convertHexStrToData:encPublicKey];
//    NSData *pri = [Tool convertHexStrToData:encPrivateKey];
//    [pub readFromByteArray:p];
//    [ecckeypair setPriKey:pri];
//    [ecckeypair setMECCPublicKeyBlob:pub];
//    [self.device setAdminPublicKey:ecckeypair.mECCPublicKeyBlob];
    return self.device;
}

-(ResultCode)importEccKeyPair:(NSString*)conName publicKey:(NSData*)publicKey privateKey:(NSData*)privateKey{
    SCApplication * app = [self getDefaultApplication];
    NSError* err;
    id<IContainer>container = [app SKF_CreateContainer:conName err:&err];
    if (err != nil || container == nil){
        NSLog(@"SKF_CreateContainer: %@",err.localizedDescription);
        if([err.localizedDescription isEqualToString:[resultCode toString:SAR_CONTAINERALREADYEXIST]] ){
            NSError* err1;
            container = [app SKF_OpenContainer:conName err:&err1];
            if(err1 != nil || container == nil){
                ResultCode rs = [container SKF_CloseContainer];
                if(rs != SAR_OK) {
                    return rs;
                }
            }
        } else {
            return SAR_FAIL;
        }
    }
    ECCPublicKeyBlob* mSignPubKeyBlob =  [ECCPublicKeyBlob new];
    BOOL e = true;
    ResultCode rs = [container SKF_CheckKeyPairExistence:e];
    if (rs == SAR_OK ) {
        NSData* pubKey = [container SKF_ExportPublicKey:YES err:&err];
        [mSignPubKeyBlob readFromByteArray:pubKey];
    }else{
        ResultCode rs = [container SKF_GenECCKeyPair:defaultPin alg:SGD_SM2_1 pubKeyBlob:&mSignPubKeyBlob];
        if(rs != SAR_OK) {
            return rs;
        }
    }
    ECCCipherBlob* symKeyCipherBlob =  [ECCCipherBlob new];
    id<ISessionKey> sessionKey = [container SKF_ECCExportSessionKey:SGD_SM4_ECB pubKeyBlob:mSignPubKeyBlob cipherBlob:&symKeyCipherBlob err:&err];
    if (err != nil || sessionKey == nil){
        NSLog(@"SKF_ECCExportSessionKey: %@",err.localizedDescription);
        return SAR_FAIL;
    }
    EnvelopedKeyBlob* mEnvelopedKeyBlob = [EnvelopedKeyBlob new];
    [mEnvelopedKeyBlob seteccCiperBlob:symKeyCipherBlob];
    [mEnvelopedKeyBlob setulSymmAlgID:SGD_SM4_ECB];
    [mEnvelopedKeyBlob setulbits:256];
    [mEnvelopedKeyBlob setversion:1];
    ECCPublicKeyBlob* mEncPubKeyBlob = [ECCPublicKeyBlob new];
    [mEncPubKeyBlob readFromByteArray:publicKey];
    [mEnvelopedKeyBlob setpubKey:mEncPubKeyBlob];
    BlockCipherParam* myBlockCipherParam =  [BlockCipherParam new];
    NSData* cipherData = nil;
    rs = [sessionKey SKF_EncryptInit:myBlockCipherParam];
    if (rs == SAR_OK) {
        cipherData = [sessionKey SKF_Encrypt:privateKey err:&err];
        NSLog(@"SKF_Encrypt:%@",[StringUtils dataToHexStr:cipherData]);
        [sessionKey SKF_CloseHandle];
        if (err != nil || cipherData == nil) {
            NSLog(@"SKF_Encrypt failed :%@",err.localizedDescription);
            return SAR_FAIL;
        }
    }
    [mEnvelopedKeyBlob setcbEncryptedPriKey:cipherData];
    rs = [container SKF_ImportECCKeyPair:defaultPin keyBlob:mEnvelopedKeyBlob];
    if(rs != SAR_OK) {
        NSLog(@"SKF_ImportECCKeyPair:%@", [resultCode toString:rs]);
        ResultCode rs1 = [container SKF_CloseContainer];
        if(rs1 != SAR_OK) {
            return rs1;
        }
        return rs;
    }
    rs = [container SKF_CloseContainer];
    if(rs != SAR_OK) {
        return rs;
    }
    return SAR_OK;
    

}


-(id<IContainer,ISignKey>)getDefaultContainer{
   
    if(self.LocalCon!=nil) {
        return self.LocalCon;
    }
    
    if(self.app==nil){
        self.app=[self getDefaultApplication];
    }
    if(self.app==nil)
        return nil;
    NSError *err = nil;
    self.LocalCon=(SCContainer *)[self.app SKF_CreateContainer:localConName err:&err];
    if(err!=nil){
        self.LocalCon = (SCContainer *)[self.app SKF_OpenContainer:localConName err:&err];
        if(self.LocalCon==nil){
            NSLog(@"MyUtils:SKF_CreateContainer: failed to create Container:%@:%@",localConName,err.localizedDescription);
            return nil;
        }else{
            err=nil;
        }
    }
    
    ECCPublicKeyBlob *signkeyBlob = [[ECCPublicKeyBlob alloc]init];
    //生成签名公钥
    if([self.LocalCon SKF_CheckKeyPairExistence:true]!=SAR_OK){
        
        ResultCode ret =[self.LocalCon SKF_GenECCKeyPair:defaultPin alg:SGD_SM2_1 pubKeyBlob:&signkeyBlob];
        if(ret!=SAR_OK){
            NSLog(@"MyUtils:SKF_GenECCKeyPair: %@",[resultCode toString:ret]);
            return nil;
        }
    }else{
        NSData *key = [self.LocalCon SKF_ExportPublicKey:YES err:&err];
        if(err!=nil){
            return nil;
        }
        [signkeyBlob readFromByteArray:key];
    }
    //导入加密密钥对
    if([self.LocalCon SKF_CheckKeyPairExistence:false]!=SAR_OK){
        //封装一个EnvelopedKeyBlob
       
        NSData *pub=[Tool convertHexStrToData:encPublicKey];
        //加密公钥
        ECCPublicKeyBlob *encpub=[[ECCPublicKeyBlob alloc]init];
        if([encpub readFromByteArray:pub]==NO){
            NSLog(@"MyUtils:set pub failed");
            return nil;
        }
        
        NSData *priData=[Tool convertHexStrToData:encPrivateKey];
        BlockCipherParam*block=[[BlockCipherParam alloc]init];
        block.paddingType=0;
        block.feedBitLen=0;
        ECCCipherBlob *cipher = nil;
        //获取会话密钥密文
        SCSession *session = [self.LocalCon SKF_ECCExportSessionKey:SGD_SM4_ECB pubKeyBlob:signkeyBlob cipherBlob:&cipher err:&err];
        if(err!=nil){
            NSLog(@"MyUtils:SKF_ECCExportSessionKey: %@",err.localizedDescription);
            return nil;
        }
        //加密初始化
        long ret = [session SKF_EncryptInit:block];
        if(SAR_OK != ret){
            NSLog(@"MyUtils:SKF_EncryptInit: rs=%@",[resultCode toString:ret]);
            return nil;
        }
        //对加密私钥进行加密
        NSData *priCipher = [session SKF_Encrypt:priData err:&err];
        if(err!=nil){
            NSLog(@"MyUtils:SKF_Encrypt: %@",err.localizedDescription);
            return nil;
        }
        [session SKF_CloseHandle];
        EnvelopedKeyBlob *env=[[EnvelopedKeyBlob alloc]init];
        [env setulSymmAlgID:SGD_SM4_ECB];
        [env setpubKey:encpub];
        [env seteccCiperBlob:cipher];
        [env setulbits:256];
        [env setversion:1];
        
        [env setcbEncryptedPriKey:priCipher];
        ret=[self.LocalCon SKF_ImportECCKeyPair:defaultPin keyBlob:env];
        
        if(SAR_OK != ret){
            NSLog(@"MyUtils:SKF_ImportECCKeyPair: rs=%@",[resultCode toString:ret]);
            return nil;
        }
    }
    return self.LocalCon;
    
}
-(id<IContainer,ISignKey>)getDefaultRemoteContainer{
    
    self.app=[self getDefaultApplication];
    
    if(self.app==nil)
    return nil;
    NSError *err = nil;
    self.CoopCon=(SCContainer *)[self.app SKF_CreateContainer:coopConName err:&err];
    if(err!=nil){
        err = nil;
        self.CoopCon = (SCContainer *)[self.app SKF_OpenContainer:coopConName err:&err];
        if(err.code == SAR_CONTAINERALREADYOPENED){
            NSLog(@"MyUtils:SKF_CreateContainer: failed to create Container:%@:%@",coopConName,err.localizedDescription);
            self.device = [self getDefaultDevice];
            [self.device SKF_DisconnectDev];
            err = nil;
            self.CoopCon = (SCContainer *)[self.app SKF_OpenContainer:coopConName err:&err];
            if(err!=nil)
            return nil;
            
        }else{
            err=nil;
        }
    }
    ServerInfo *server = [[ServerInfo alloc]init];
    server.ip = IP;
    server.port = port;
    NSArray *arr = [NSArray arrayWithObjects:server, nil];
    
    NSInteger ret = [self.CoopCon setServerAuthInfo:appID appSecret:appSecret list:arr];
    //生成签名公钥
    ECCPublicKeyBlob *signKeyBlob = [[ECCPublicKeyBlob alloc]init];
    if([self.CoopCon SKF_CheckKeyPairExistence:true]!=SAR_OK){
        ResultCode ret =[self.CoopCon SKF_GenECCKeyPair:defaultPin alg:SGD_SM2_1 appID:appID appSecret:appSecret list:arr pubKeyBlob:&signKeyBlob];
        if(ret!=SAR_OK){
            NSLog(@"MyUtils:SKF_GenECCKeyPair: %@",[resultCode toString:ret]);
            return nil;
        }else{
            err=nil;
       
        }
    }else{
        NSData *key = [self.LocalCon SKF_ExportPublicKey:YES err:&err];
        if(err!=nil){
            return nil;
        }
        [signKeyBlob readFromByteArray:key];
    }
    //导入加密密钥对
    if([self.CoopCon SKF_CheckKeyPairExistence:false]!=SAR_OK){
        //封装一个EnvelopedKeyBlob
      
        NSData *pub=[Tool convertHexStrToData:encPublicKey];
        //加密公钥
        ECCPublicKeyBlob *encpub=[[ECCPublicKeyBlob alloc]init];
        if([encpub readFromByteArray:pub]==NO){
            NSLog(@"MyUtils:set pub failed");
            return nil;
        }
        NSData *priData=[Tool convertHexStrToData:encPrivateKey];
        BlockCipherParam*block=[[BlockCipherParam alloc]init];
        block.paddingType=0;
        block.feedBitLen=0;
        ECCCipherBlob *cipher = nil;
        //获取会话密钥密文
        SCSession *session = [self.CoopCon SKF_ECCExportSessionKey:SGD_SM4_ECB pubKeyBlob:self.signPubkey cipherBlob:&cipher err:&err];
        if(err!=nil){
            NSLog(@"MyUtils:SKF_ECCExportSessionKey: %@",err.localizedDescription);
            return nil;
        }
        //加密初始化
        long ret = [session SKF_EncryptInit:block];
        if(SAR_OK != ret){
            NSLog(@"MyUtils:SKF_EncryptInit: rs=%@",[resultCode toString:ret]);
            return nil;
        }
        //对加密私钥进行加密
        NSData *priCipher = [session SKF_Encrypt:priData err:&err];
        if(err!=nil){
            NSLog(@"MyUtils:SKF_Encrypt: %@",err.localizedDescription);
            return nil;
        }
        [session SKF_CloseHandle];
        EnvelopedKeyBlob *env=[[EnvelopedKeyBlob alloc]init];
        [env setulSymmAlgID:SGD_SM4_ECB];
        [env setpubKey:encpub];
        [env seteccCiperBlob:cipher];
        [env setulbits:256];
        [env setversion:1];
        
        [env setcbEncryptedPriKey:priCipher];
        ret=[self.CoopCon SKF_ImportECCKeyPair:defaultPin keyBlob:env];
        
        if(SAR_OK != ret){
            NSLog(@"MyUtils:SKF_ImportECCKeyPair: rs=%@",[resultCode toString:ret]);
            return nil;
        }
    }
    
    return self.CoopCon;
    
}

-(SCApplication*)getDefaultApplication{
   if(self.app !=nil)
    return self.app;
    self.device=[self getDefaultDevice];
    
    NSError *err = nil;
    self.app = [self.device SKF_CreateApplication:appName err:&err];
    if(err!=nil){
        self.app = [self.device SKF_OpenApplication:appName err:&err];
        if(self.app==nil){
            NSLog(@"MyUtils:SKF_CreateApplication: failed to create app:%@:%@",appName,err.localizedDescription);
            return nil;
        }
    }
    return self.app;
}

-(void)cleanDevice{
    self.device = [SecureCoreDevice sharedCoreDevice];
    ResultCode ret = [self.device SKF_DisconnectDev];
    NSArray *appList=nil;
    ret = [self.device SKF_EnumApplication:&appList];
    if(ret!=SAR_OK)
        NSLog(@"EnumApplication is failed");
    for(NSString *appName in appList){
        [self.device SKF_DeleteApplication:appName];
    }
    //将变量清空，下次使用时重新赋值
    self.app = nil;
    self.LocalCon = nil;
    self.CoopCon = nil;
    self.device = nil;

}
@end
