//
//  SecureCoreDevice.h
//  SecurecoreMoreKey
//
//  Created by SecureChip on 2018/1/2.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "IDevice.h"
#import "SCElement.h"
@interface SecureCoreDevice : SCElement<IDevice>
+(instancetype)sharedCoreDevice;
@end
