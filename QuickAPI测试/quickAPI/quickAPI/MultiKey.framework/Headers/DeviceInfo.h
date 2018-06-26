//
//  DeviceInfo.h
//  SecurityCoreSDK
//
//  Created by 赵利 on 2017/11/14.
//  Copyright © 2017年 赵利. All rights reserved.
//

#import <Foundation/Foundation.h>
@interface Version : NSObject
@property (strong,nonatomic) NSData *min;
@property (strong,nonatomic) NSData *max;
@end

@interface DeviceInfo : NSObject
@property (strong,nonatomic,readonly) Version *mVersion;
@property (assign,nonatomic,readonly) int MaxReservedByteCount;
@property (copy,nonatomic,readonly) NSString *mManufacturer;
@property (copy,nonatomic,readonly) NSString *mIssuer;
@property (copy,nonatomic,readonly) NSString *mSerialNumber;
@property (strong,nonatomic,readonly) Version *mHardwareVersion;
@property (strong,nonatomic,readonly) Version *mFirmwareVersion;
@property (assign,nonatomic,readonly) long *mAlgSymCap;
@property (assign,nonatomic,readonly) long *mMalSymCap;
@property (assign,nonatomic,readonly) long *mAlgHashCap;
@property (assign,nonatomic,readonly) long *mDevAuthAlgId;
@property (assign,nonatomic,readonly) long *mTotleSpace;
@property (assign,nonatomic,readonly) long *mFreeSpace;
@property (assign,nonatomic,readonly) long *mMaxEccBufferSize;
@property (assign,nonatomic,readonly) long *mMaxBufferSize;
@property (strong,nonatomic,readonly) NSData *mReserved;
@end
