//
//  SSLTestAppDelegate.h
//  SSLTest
//
//  Created by Dimitri Bouniol on 7/10/11.
//  Copyright 2011 Mochi Development Inc. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <Security/Security.h>
#import "AsyncSocket.h"

@interface SSLTestAppDelegate : NSObject <NSApplicationDelegate> {
    NSWindow *window;
    NSTextView *textField1;
    NSTextView *textField2;
    
    AsyncSocket *listener;
    AsyncSocket *client;
    
    AsyncSocket *speaker;
    
    NSDictionary *tls1;
    NSDictionary *tls2;
}

@property (assign) IBOutlet NSWindow *window;
@property (assign) IBOutlet NSTextView *textField1;
@property (assign) IBOutlet NSTextView *textField2;
@property (retain) AsyncSocket *client;

- (void)createTLS1;
- (IBAction)ssl1:(id)sender;
- (IBAction)hi1:(id)sender;
- (IBAction)listen1:(id)sender;

- (void)createTLS2;
- (IBAction)ssl2:(id)sender;
- (IBAction)hi2:(id)sender;
- (IBAction)listen2:(id)sender;
- (IBAction)start2:(id)sender;

- (void)logInfo:(NSString *)msg textView:(NSTextView *)textView;
- (void)logMessage:(NSString *)msg textView:(NSTextView *)textView;
- (void)logError:(NSString *)msg textView:(NSTextView *)textView;

@end
