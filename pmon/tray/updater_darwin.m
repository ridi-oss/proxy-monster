#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

#include "updater_darwin.h"

extern void goUpdateReady(char *version, bool interactive);

// Sparkle is loaded at run time, so a build without it (a `go build`, the tests) still links. These declare
// the few Sparkle methods called; the delegate's are found by selector.
@protocol PMSparkleUpdater <NSObject>
@property(nonatomic) BOOL automaticallyChecksForUpdates;
@property(nonatomic) BOOL automaticallyDownloadsUpdates;
@end

@protocol PMSparkleController <NSObject>
- (instancetype)initWithStartingUpdater:(BOOL)start updaterDelegate:(id)updaterDelegate userDriverDelegate:(id)userDriverDelegate;
- (id<PMSparkleUpdater>)updater;
- (void)checkForUpdates:(id)sender;
@end

@interface PMUpdaterDelegate : NSObject
@end

static void (^pendingInstall)(void);
static BOOL installing;

static void hold(id item, void (^block)(void), bool interactive) {
  pendingInstall = [block copy];
  NSString *v = [item valueForKey:@"displayVersionString"];
  goUpdateReady((char *)(v ?: @"").UTF8String, interactive);
}

@implementation PMUpdaterDelegate
// Holds a downloaded update until no database connection is open, instead of installing it at quit, which a
// menu-bar app rarely does.
- (BOOL)updater:(id)updater willInstallUpdateOnQuit:(id)item immediateInstallationBlock:(void (^)(void))block {
  hold(item, block, false);
  return YES;
}

// Install and Relaunch from Sparkle's own window takes the same path, so it asks before dropping connections
// and replaces the daemon after the relaunch.
- (BOOL)updater:(id)updater shouldPostponeRelaunchForUpdate:(id)item untilInvokingBlock:(void (^)(void))block {
  if (installing) {
    return NO;
  }
  hold(item, block, true);
  return YES;
}

// Sparkle otherwise asks a background app to implement this, since a scheduled alert cannot take focus.
- (BOOL)supportsGentleScheduledUpdateReminders {
  return YES;
}
@end

static id<PMSparkleController> controller;
static PMUpdaterDelegate *updaterDelegate;

// Only release builds carry a feed (build-app.sh).
bool pm_updates_configured(void) { return [[NSBundle mainBundle] objectForInfoDictionaryKey:@"SUFeedURL"] != nil; }

bool pm_updates_auto(void) {
  id v = [[NSUserDefaults standardUserDefaults] objectForKey:@"SUEnableAutomaticChecks"];
  if (v == nil) {
    v = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"SUEnableAutomaticChecks"];
  }
  return [v boolValue];
}

// An organization can turn updates off with a configuration profile; the setting is then read-only.
bool pm_updates_forced(void) {
  return [[NSUserDefaults standardUserDefaults] objectIsForcedForKey:@"SUEnableAutomaticChecks"];
}

bool pm_updater_start(void) {
  if (!pm_updates_configured()) {
    return false;
  }
  NSString *path = [[NSBundle mainBundle].privateFrameworksPath stringByAppendingPathComponent:@"Sparkle.framework"];
  NSError *error = nil;
  if (![[NSBundle bundleWithPath:path] loadAndReturnError:&error]) {
    NSLog(@"pmontray: Sparkle did not load: %@", error);
    return false;
  }
  Class cls = NSClassFromString(@"SPUStandardUpdaterController");
  if (cls == nil) {
    return false;
  }
  void (^create)(void) = ^{
    updaterDelegate = [PMUpdaterDelegate new];
    controller = [[cls alloc] initWithStartingUpdater:YES updaterDelegate:updaterDelegate userDriverDelegate:updaterDelegate];
  };
  if ([NSThread isMainThread]) {
    create();
  } else {
    dispatch_sync(dispatch_get_main_queue(), create);
  }
  return controller != nil;
}

void pm_updater_check(void) {
  dispatch_async(dispatch_get_main_queue(), ^{
    [NSApp activateIgnoringOtherApps:YES];
    [controller checkForUpdates:nil];
  });
}

void pm_updater_set_auto(bool on) {
  dispatch_async(dispatch_get_main_queue(), ^{
    controller.updater.automaticallyChecksForUpdates = on;
    controller.updater.automaticallyDownloadsUpdates = on;
  });
}

// Installs the held update; Sparkle then relaunches the app. The block stays held: Sparkle may need it again
// if the termination it starts is canceled.
void pm_updater_install(void) {
  dispatch_async(dispatch_get_main_queue(), ^{
    if (pendingInstall) {
      installing = YES;
      pendingInstall();
    }
  });
}
