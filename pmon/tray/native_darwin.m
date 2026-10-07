#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#import <UserNotifications/UserNotifications.h>

#include "native_darwin.h"

extern void goNotificationClicked(char *key);
extern void goURLOpened(char *url);

@interface PMNotificationDelegate : NSObject <UNUserNotificationCenterDelegate>
@end

@implementation PMNotificationDelegate
// A menu-bar app is rarely frontmost; without this, macOS hides banners while it is.
- (void)userNotificationCenter:(UNUserNotificationCenter *)center
       willPresentNotification:(UNNotification *)notification
         withCompletionHandler:(void (^)(UNNotificationPresentationOptions))completionHandler {
  completionHandler(UNNotificationPresentationOptionBanner | UNNotificationPresentationOptionList);
}

- (void)userNotificationCenter:(UNUserNotificationCenter *)center
    didReceiveNotificationResponse:(UNNotificationResponse *)response
             withCompletionHandler:(void (^)(void))completionHandler {
  NSString *key = response.notification.request.content.userInfo[@"key"];
  if (key.length > 0) {
    goNotificationClicked((char *)key.UTF8String);
  }
  completionHandler();
}
@end

static PMNotificationDelegate *delegate;

// UNUserNotificationCenter raises if the process is not a bundled app (a `go run` build), so every entry point
// checks for a bundle identifier first.
static bool bundled(void) { return [[NSBundle mainBundle] bundleIdentifier] != nil; }

bool pm_notifications_init(void) {
  if (!bundled()) {
    return false;
  }
  UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
  delegate = [PMNotificationDelegate new];
  center.delegate = delegate;
  [center requestAuthorizationWithOptions:(UNAuthorizationOptionAlert | UNAuthorizationOptionSound)
                        completionHandler:^(BOOL granted, NSError *error){
                        }];
  return true;
}

bool pm_notify(const char *ident, const char *title, const char *body, const char *key) {
  if (!bundled()) {
    return false;
  }
  UNMutableNotificationContent *content = [UNMutableNotificationContent new];
  content.title = [NSString stringWithUTF8String:title];
  content.body = [NSString stringWithUTF8String:body];
  content.userInfo = @{@"key" : [NSString stringWithUTF8String:key]};
  UNNotificationRequest *request =
      [UNNotificationRequest requestWithIdentifier:[NSString stringWithUTF8String:ident] content:content trigger:nil];
  [[UNUserNotificationCenter currentNotificationCenter] addNotificationRequest:request withCompletionHandler:nil];
  return true;
}

int pm_login_item_status(void) {
  if (!bundled()) {
    return PM_LOGIN_UNSUPPORTED;
  }
  if (@available(macOS 13, *)) {
    // Awaiting approval in System Settings is still registered: showing it off would make the toggle register
    // again instead of letting the user turn it off.
    SMAppServiceStatus status = SMAppService.mainAppService.status;
    return status == SMAppServiceStatusEnabled || status == SMAppServiceStatusRequiresApproval ? PM_LOGIN_ON
                                                                                               : PM_LOGIN_OFF;
  }
  return PM_LOGIN_UNSUPPORTED;
}

char *pm_set_login_item(bool on) {
  if (@available(macOS 13, *)) {
    NSError *error = nil;
    BOOL ok = on ? [SMAppService.mainAppService registerAndReturnError:&error]
                 : [SMAppService.mainAppService unregisterAndReturnError:&error];
    if (ok && on && SMAppService.mainAppService.status == SMAppServiceStatusRequiresApproval) {
      [SMAppService openSystemSettingsLoginItems];
      return strdup("needs-approval");
    }
    if (ok) {
      return NULL;
    }
    return strdup(error.localizedDescription.UTF8String);
  }
  return strdup("needs-macos-13");
}

bool pm_pref_bool(const char *key) {
  return [[NSUserDefaults standardUserDefaults] boolForKey:[NSString stringWithUTF8String:key]];
}

void pm_set_pref_bool(const char *key, bool value) {
  [[NSUserDefaults standardUserDefaults] setBool:value forKey:[NSString stringWithUTF8String:key]];
}

void pm_activate_pid(int pid) {
  dispatch_async(dispatch_get_main_queue(), ^{
    [[NSRunningApplication runningApplicationWithProcessIdentifier:pid]
        activateWithOptions:NSApplicationActivateAllWindows];
  });
}

@interface PMURLHandler : NSObject
@end

@implementation PMURLHandler
- (void)handleURL:(NSAppleEventDescriptor *)event withReplyEvent:(NSAppleEventDescriptor *)reply {
  NSString *url = [[event paramDescriptorForKeyword:keyDirectObject] stringValue];
  if (url.length > 0) {
    goURLOpened((char *)url.UTF8String);
  }
}
@end

static PMURLHandler *urlHandler;

// Registered before the run loop starts, so a link that launches the app is not dropped.
void pm_url_init(void) {
  urlHandler = [PMURLHandler new];
  [[NSAppleEventManager sharedAppleEventManager] setEventHandler:urlHandler
                                                     andSelector:@selector(handleURL:withReplyEvent:)
                                                   forEventClass:kInternetEventClass
                                                      andEventID:kAEGetURL];
}

char *pm_pref_string(const char *key) {
  NSString *v = [[NSUserDefaults standardUserDefaults] stringForKey:[NSString stringWithUTF8String:key]];
  return v ? strdup(v.UTF8String) : NULL;
}

void pm_set_pref_string(const char *key, const char *value) {
  [[NSUserDefaults standardUserDefaults] setObject:[NSString stringWithUTF8String:value]
                                            forKey:[NSString stringWithUTF8String:key]];
}

// The user's languages in order, newline-separated.
char *pm_preferred_languages(void) {
  return strdup([[NSLocale preferredLanguages] componentsJoinedByString:@"\n"].UTF8String);
}

// mode 0 follows the system, 1 is light, 2 is dark. A NULL window sets the whole app, which the menu-bar
// menu follows.
void pm_set_appearance(void *window, int mode) {
  // A strong reference taken now, so a window closed before the block runs is still valid when it does.
  NSWindow *w = window ? (__bridge NSWindow *)window : nil;
  dispatch_async(dispatch_get_main_queue(), ^{
    NSAppearance *appearance = nil;
    if (mode == 1) appearance = [NSAppearance appearanceNamed:NSAppearanceNameAqua];
    if (mode == 2) appearance = [NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
    if (w) {
      w.appearance = appearance;
    } else {
      NSApp.appearance = appearance;
    }
  });
}
