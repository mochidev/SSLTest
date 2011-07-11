//
//  SSLTestAppDelegate.m
//  SSLTest
//
//  Created by Dimitri Bouniol on 7/10/11.
//  Copyright 2011 Mochi Development Inc. All rights reserved.
//

#import "SSLTestAppDelegate.h"

@implementation SSLTestAppDelegate

@synthesize window;
@synthesize textField1;
@synthesize textField2, client;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    listener = [[AsyncSocket alloc] initWithDelegate:self];
    speaker = [[AsyncSocket alloc] initWithDelegate:self];
    
    [listener acceptOnInterface:@"loopback" port:0 error:NULL];
    [self logInfo:[NSString stringWithFormat:@"Listening on %d", [listener localPort]] textView:textField1];
    
}

- (void)onSocketDidSecure:(AsyncSocket *)sock
{
    if (sock == listener || sock == client) {
        [self logMessage:@"Did Secure!" textView:textField1];
    } else {
        [self logMessage:@"Did Secure!" textView:textField2];
    }
}

- (void)onSocketDidDisconnect:(AsyncSocket *)sock
{
    if (sock == listener || sock == client) {
        [self logInfo:@"Disconnected" textView:textField1];
    } else {
        [self logInfo:@"Disconnected" textView:textField2];
    }
}

- (void)onSocket:(AsyncSocket *)sock willDisconnectWithError:(NSError *)err
{
    if (sock == listener || sock == client) {
        [self logError:[err description] textView:textField1];
    } else {
        [self logError:[err description] textView:textField2];
    }
}

- (void)onSocket:(AsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag
{
    NSString *message = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    if (sock == listener || sock == client) {
        [self logMessage:[message substringToIndex:[message length]-2] textView:textField1];
    } else {
        [self logMessage:[message substringToIndex:[message length]-2] textView:textField2];
    }
    
    [message release];
}

- (void)onSocket:(AsyncSocket *)sock didConnectToHost:(NSString *)host port:(UInt16)port
{
    if (sock == listener || sock == client) {
        [self logInfo:[NSString stringWithFormat:@"Connected: %@, %d", host, port] textView:textField1];
    } else {
        [self logInfo:[NSString stringWithFormat:@"Connected: %@, %d", host, port] textView:textField2];
    }
}

- (void)onSocket:(AsyncSocket *)sock didAcceptNewSocket:(AsyncSocket *)newSocket
{
    self.client = newSocket;
    [self logInfo:@"Accepted New Socket" textView:textField1];
}

- (void)createTLS1
{
//    NSData *certificateData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"eVueServerCertificate" ofType:@"der"]];
    
    // Declare any Carbon variables we may create
	// We do this here so it's easier to compare to the bottom of this method where we release them all
	SecKeychainRef keychain = NULL;
	SecIdentitySearchRef searchRef = NULL;
	
	NSMutableArray *certificates = [[NSMutableArray alloc] init];
	
	SecKeychainCopyDefault(&keychain);
	SecIdentitySearchCreate(keychain, CSSM_KEYUSE_ANY, &searchRef);
	
	SecIdentityRef currentIdentityRef = NULL;
	while (searchRef && (SecIdentitySearchCopyNext(searchRef, &currentIdentityRef) != errSecItemNotFound)) {
		// Extract the private key from the identity, and examine it to see if it will work for us
		SecKeyRef privateKeyRef = NULL;
		SecIdentityCopyPrivateKey(currentIdentityRef, &privateKeyRef);
		
		if (privateKeyRef) {
			SecItemAttr itemAttributes[] = {kSecKeyPrintName};
			
			SecExternalFormat externalFormats[] = {kSecFormatUnknown};
			
			int itemAttributesSize  = sizeof(itemAttributes) / sizeof(*itemAttributes);
			int externalFormatsSize = sizeof(externalFormats) / sizeof(*externalFormats);
			NSAssert(itemAttributesSize == externalFormatsSize, @"Arrays must have identical counts!");
			
			SecKeychainAttributeInfo info = {itemAttributesSize, (void *)&itemAttributes, (void *)&externalFormats};
			
			SecKeychainAttributeList *privateKeyAttributeList = NULL;
			SecKeychainItemCopyAttributesAndData((SecKeychainItemRef)privateKeyRef,
			                                     &info, NULL, &privateKeyAttributeList, NULL, NULL);
			
			if (privateKeyAttributeList) {
//				SecKeychainAttribute nameAttribute = privateKeyAttributeList->attr[0];
				
//				NSString *name = [[[NSString alloc] initWithBytes:nameAttribute.data
//														   length:(nameAttribute.length)
//														 encoding:NSUTF8StringEncoding] autorelease];
                
                //                NSLog(@"name is %@", name);
				
				// Ugly Hack
				// For some reason, name sometimes contains odd characters at the end of it
				// I'm not sure why, and I don't know of a proper fix, thus the use of the hasPrefix: method
//				if ([name hasPrefix:@"eVue"])
//				{
					// It's possible for there to be more than one private key with the above prefix
					// But we're only allowed to have one identity, so we make sure to only add one to the array
					if ([certificates count] == 0) {
						[certificates addObject:(id)currentIdentityRef];
					}
//				}
				
				SecKeychainItemFreeAttributesAndData(privateKeyAttributeList, NULL);
			}
			
			CFRelease(privateKeyRef);
		}
		
		CFRelease(currentIdentityRef);
	}
	
	if(keychain)  CFRelease(keychain);
	if(searchRef) CFRelease(searchRef);
    
    tls1 = [[NSDictionary alloc] initWithObjectsAndKeys:(id)kCFStreamSocketSecurityLevelNegotiatedSSL, (id)kCFStreamSSLLevel,
                                                        certificates, (id)kCFStreamSSLCertificates,
                                                        (id)kCFBooleanTrue, (id)kCFStreamSSLIsServer, nil];
    
    [certificates release];
}

- (IBAction)ssl1:(id)sender
{
    if (!tls1)
        [self createTLS1];
    [client startTLS:tls1];
}

- (IBAction)hi1:(id)sender
{
    NSMutableData *data = [NSMutableData dataWithData:[@"Hello, World!" dataUsingEncoding:NSUTF8StringEncoding]];
    [data appendData:[AsyncSocket CRLFData]];
    
    [client writeData:data withTimeout:10 tag:1];
}

- (IBAction)listen1:(id)sender
{
    [client readDataToData:[AsyncSocket CRLFData] withTimeout:10 maxLength:100000 tag:2];
}

- (void)createTLS2
{
    tls2 = [[NSDictionary alloc] initWithObjectsAndKeys:(id)kCFStreamSocketSecurityLevelNegotiatedSSL, (id)kCFStreamSSLLevel,
                                                        (id)kCFBooleanFalse, (id)kCFStreamSSLAllowsExpiredCertificates,
                                                        (id)kCFBooleanFalse, (id)kCFStreamSSLAllowsExpiredRoots,
                                                        (id)kCFBooleanTrue, (id)kCFStreamSSLAllowsAnyRoot,
                                                        (id)kCFBooleanFalse, (id)kCFStreamSSLValidatesCertificateChain, nil];
}

- (IBAction)ssl2:(id)sender
{
    if (!tls2)
        [self createTLS2];
    [speaker startTLS:tls2];
}

- (IBAction)hi2:(id)sender
{
    NSMutableData *data = [NSMutableData dataWithData:[@"Hello, World!" dataUsingEncoding:NSUTF8StringEncoding]];
    [data appendData:[AsyncSocket CRLFData]];
    
    [speaker writeData:data withTimeout:10 tag:1];
}

- (IBAction)listen2:(id)sender
{
    [speaker readDataToData:[AsyncSocket CRLFData] withTimeout:10 maxLength:100000 tag:2];
}

- (IBAction)start2:(id)sender
{
    [speaker connectToHost:@"localhost" onPort:[listener localPort] error:NULL];
}

- (void)scrollToBottomOfTextView:(NSTextView *)textView
{
	NSScrollView *scrollView = [textView enclosingScrollView];
	NSPoint newScrollOrigin;
	
	if ([[scrollView documentView] isFlipped])
		newScrollOrigin = NSMakePoint(0.0F, NSMaxY([[scrollView documentView] frame]));
	else
		newScrollOrigin = NSMakePoint(0.0F, 0.0F);
	
	[[scrollView documentView] scrollPoint:newScrollOrigin];
}

- (void)logError:(NSString *)msg textView:(NSTextView *)textView
{
	NSString *paragraph = [NSString stringWithFormat:@"%@\n", msg];
	
	NSMutableDictionary *attributes = [NSMutableDictionary dictionaryWithCapacity:1];
	[attributes setObject:[NSColor redColor] forKey:NSForegroundColorAttributeName];
    [attributes setObject:[NSFont fontWithName:@"Menlo-Bold" size:11] forKey:NSFontAttributeName];
	
	NSAttributedString *as = [[NSAttributedString alloc] initWithString:paragraph attributes:attributes];
	[as autorelease];
	
	[[textView textStorage] appendAttributedString:as];
	[self scrollToBottomOfTextView:textView];
}

- (void)logInfo:(NSString *)msg textView:(NSTextView *)textView
{
	NSString *paragraph = [NSString stringWithFormat:@"%@\n", msg];
	
	NSMutableDictionary *attributes = [NSMutableDictionary dictionaryWithCapacity:1];
	[attributes setObject:[NSColor grayColor] forKey:NSForegroundColorAttributeName];
    [attributes setObject:[NSFont fontWithName:@"Menlo-Regular" size:11] forKey:NSFontAttributeName];
	
	NSAttributedString *as = [[NSAttributedString alloc] initWithString:paragraph attributes:attributes];
	[as autorelease];
	
	[[textView textStorage] appendAttributedString:as];
	[self scrollToBottomOfTextView:textView];
}

- (void)logMessage:(NSString *)msg textView:(NSTextView *)textView
{
	NSString *paragraph = [NSString stringWithFormat:@"%@\n", msg];
	
	NSMutableDictionary *attributes = [NSMutableDictionary dictionaryWithCapacity:1];
	[attributes setObject:[NSColor blackColor] forKey:NSForegroundColorAttributeName];
    [attributes setObject:[NSFont fontWithName:@"Menlo-Regular" size:11] forKey:NSFontAttributeName];
	
	NSAttributedString *as = [[NSAttributedString alloc] initWithString:paragraph attributes:attributes];
	[as autorelease];
	
	[[textView textStorage] appendAttributedString:as];
	[self scrollToBottomOfTextView:textView];
}

- (void)dealloc
{
    [tls1 release];
    [tls2 release];
    [client release];
    
    [listener release];
    [speaker release];
    
    [super dealloc];
}

@end
