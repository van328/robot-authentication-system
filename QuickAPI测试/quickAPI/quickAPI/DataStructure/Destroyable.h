//
//  Destroyable.h
//  quickAPI
//
//  Created by 赵利 on 2018/2/8.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol Destroyable <NSObject>
/**
 销毁此对象。
 */
- (void) destroy ;
/**
 判断对象是否销毁

 @return YES 已销毁 NO 未销毁
 */
- (BOOL) isDestroyed;
@end
