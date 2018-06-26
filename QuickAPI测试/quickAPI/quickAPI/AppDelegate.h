//
//  AppDelegate.h
//  quickAPI
//
//  Created by SecureChip on 2018/1/30.
//  Copyright © 2018年 IIE. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <CoreData/CoreData.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;

@property (readonly, strong) NSPersistentContainer *persistentContainer;

- (void)saveContext;


@end

