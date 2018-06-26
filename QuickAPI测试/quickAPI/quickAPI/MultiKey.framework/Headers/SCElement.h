//
//  SCElement.h
//  SecurecoreMoreKey
//
//  Created by SecureChip on 2018/1/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "IElement.h"
@interface SCElement : NSObject<IElement>
-(instancetype)initWithParam:(id<IElement>)parent handle:(NSInteger)handle name:(NSString *)name ;
@end
