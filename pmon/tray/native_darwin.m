#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#import <UserNotifications/UserNotifications.h>

#include "native_darwin.h"

extern void goNotificationClicked(char *key);

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
      return strdup("Allow Proxy Monster Desktop under Login Items in System Settings to finish.");
    }
    if (ok) {
      return NULL;
    }
    return strdup(error.localizedDescription.UTF8String);
  }
  return strdup("Open at Login needs macOS 13 or later");
}

bool pm_pref_bool(const char *key) {
  return [[NSUserDefaults standardUserDefaults] boolForKey:[NSString stringWithUTF8String:key]];
}

void pm_set_pref_bool(const char *key, bool value) {
  [[NSUserDefaults standardUserDefaults] setBool:value forKey:[NSString stringWithUTF8String:key]];
}
