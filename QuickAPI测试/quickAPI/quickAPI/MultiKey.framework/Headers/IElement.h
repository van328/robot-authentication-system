//
//  IElement.h
//  sctest_morekey
//
//  Created by SecureChip on 2017/12/27.
//  Copyright © 2017年 IIE. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "IClose.h"
#import "resultCode.h"
#import "IElement.h"


/**
 * 密码对象管理接口
 * Created by Nick on 2017/3/10.
 */

@protocol IElement <IClose>
/**
 * 获取名称
 *
 * @return 名称
 */
-(NSString*)getName;
/**
 * 获取句柄
 *
 * @return 句柄
 */
-(NSInteger)getHandle;

/**
 * 获取父元素
 *
 * @return 父元素
 */
-(id<IElement>)getParent;
/**
 * 复制自身
 *
 * @return 复制的对象
 */
-(id<IElement>)copy;
/**
 *
 */
/**
 判断对象是否打开

 @return 布尔型
 */
-(BOOL)isOpened;


@end
