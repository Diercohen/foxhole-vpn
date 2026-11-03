// foxhole-wifi: the Wi-Fi's name, which macOS (14.4+) gives only to apps allowed Location. It sits in Foxhole.app's
// Contents/MacOS, so it's Foxhole that macOS asks about and allows (Info.plist's NSLocationUsageDescription), once.
// Prints two lines: allowed / denied / unasked, then the name (empty if not known). `foxhole-wifi ask` first asks,
// where it's not been asked yet, and waits up to two minutes for the answer. Built by `npm run wifi` (macOS only).
#import <CoreLocation/CoreLocation.h>
#import <CoreWLAN/CoreWLAN.h>

int main(int argc, char **argv) {
  @autoreleasepool {
    CLLocationManager *m = [CLLocationManager new];
    if (argc > 1 && !strcmp(argv[1], "ask") && m.authorizationStatus == kCLAuthorizationStatusNotDetermined) {
      [m requestWhenInUseAuthorization];
      NSDate *end = [NSDate dateWithTimeIntervalSinceNow:120];
      while (m.authorizationStatus == kCLAuthorizationStatusNotDetermined && end.timeIntervalSinceNow > 0)
        [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.25]];
    }
    CLAuthorizationStatus s = m.authorizationStatus;
    const char *how = s == kCLAuthorizationStatusNotDetermined ? "unasked"
      : s == kCLAuthorizationStatusDenied || s == kCLAuthorizationStatusRestricted ? "denied" : "allowed";
    NSString *ssid = CWWiFiClient.sharedWiFiClient.interface.ssid;
    printf("%s\n%s\n", how, ssid.UTF8String ?: "");
  }
  return 0;
}
