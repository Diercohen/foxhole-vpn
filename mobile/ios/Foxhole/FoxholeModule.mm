// Foxhole's native side on iOS, as FoxholeModule.kt, Core.kt and Phone.kt are on Android: the window's way to the core
// (specs/NativeFoxhole.ts); the core itself, node/main.mjs in nodejs-mobile's Node, started once per process; and what
// it asks of the phone (main.mjs `ask`). A socket pair carries lines of JSON both ways.
#import <AVFoundation/AVFoundation.h>
#import <FoxholeSpec/FoxholeSpec.h>
#import <Network/Network.h>
#import <NodeMobile/NodeMobile.h>
#import <UIKit/UIKit.h>
#import <os/log.h>
#import <sys/socket.h>

#include <mutex>
#include <string>
#include <vector>

@interface FoxholeModule : NativeFoxholeSpecBase <NativeFoxholeSpec>
@end

static os_log_t say = os_log_create("io.github.diercohen.foxhole", "foxhole");
static int mine = -1; // this side of the socket pair
static std::mutex writing;
static __weak FoxholeModule *listener; // the window's, while there's one

/** A line of JSON to the core. */
static void toCore(NSString *line) {
  if (mine < 0) return;
  std::string s = std::string(line.UTF8String) + "\n";
  std::lock_guard<std::mutex> lock(writing);
  for (size_t at = 0; at < s.size();) {
    ssize_t n = write(mine, s.data() + at, s.size() - at);
    if (n <= 0) return;
    at += n;
  }
}

/** The answer to the core's ask `seq`: a value, or an error. */
static void reply(int seq, id value, NSString *error) {
  NSDictionary *m = error ? @{@"t" : @"answer", @"id" : @(seq), @"error" : error} : @{@"t" : @"answer", @"id" : @(seq), @"v" : value ?: NSNull.null};
  toCore([[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:m options:0 error:nil] encoding:NSUTF8StringEncoding]);
}

/** Calls `each` with each line read from `fd`, until it closes. */
static void readLines(int fd, void (^each)(const std::string &)) {
  char buf[16384];
  std::string line;
  for (ssize_t n; (n = read(fd, buf, sizeof buf)) > 0;) {
    line.append(buf, n);
    for (size_t i; (i = line.find('\n')) != std::string::npos; line.erase(0, i + 1)) each(line.substr(0, i));
  }
}

// ── What the core asks of the phone ──────────────────────────────────────────────────────────────────────────

static dispatch_queue_t phone; // the network's state is kept, and read, here
static NSString *net; // what the phone is online through, as the window's Network card says it; nil offline
static AVAudioPlayer *silence; // playing while connected

/** Half a second of silence, as a WAV file (8 kHz, 16-bit mono). */
static NSData *silentWav() {
  const uint32_t bytes = 8000;
  NSMutableData *wav = [NSMutableData dataWithLength:44 + bytes]; // zeros: the samples are silence
  auto h = static_cast<uint8_t *>(wav.mutableBytes);
  auto put = [&](int at, uint32_t v, int size) { memcpy(h + at, &v, size); };
  memcpy(h, "RIFF", 4), put(4, 36 + bytes, 4), memcpy(h + 8, "WAVEfmt ", 8), put(16, 16, 4), put(20, 1, 2), put(22, 1, 2);
  put(24, 8000, 4), put(28, 16000, 4), put(32, 2, 2), put(34, 16, 2), memcpy(h + 36, "data", 4), put(40, bytes, 4);
  return wav;
}

/**
 * iOS suspends an app soon after it leaves the screen, and its proxy with it: while connected, Foxhole plays silence
 * (mixed with other apps' sound), which keeps it running for the apps that use the proxy, as Android's notification does.
 */
static void keepAlive(BOOL on) {
  AVAudioSession *session = AVAudioSession.sharedInstance;
  if (!on) {
    [silence stop];
    silence = nil;
    [session setActive:NO withOptions:AVAudioSessionSetActiveOptionNotifyOthersOnDeactivation error:nil];
  } else if (!silence) {
    [session setCategory:AVAudioSessionCategoryPlayback withOptions:AVAudioSessionCategoryOptionMixWithOthers error:nil];
    [session setActive:YES error:nil];
    silence = [[AVAudioPlayer alloc] initWithData:silentWav() error:nil];
    silence.numberOfLoops = -1;
    [silence play];
  }
}

/** Whether iOS trusts relay mode's certificate: its profile installed, and turned on in Certificate Trust Settings. */
static BOOL caTrusted(NSString *pem) {
  NSString *b64 = [pem stringByReplacingOccurrencesOfString:@"-----[^-]+-----" withString:@"" options:NSRegularExpressionSearch range:NSMakeRange(0, pem.length)];
  NSData *der = [[NSData alloc] initWithBase64EncodedString:b64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
  SecCertificateRef ca = der ? SecCertificateCreateWithData(NULL, (__bridge CFDataRef)der) : NULL;
  if (!ca) return NO;
  SecPolicyRef policy = SecPolicyCreateBasicX509();
  SecTrustRef trust = NULL;
  BOOL ok = SecTrustCreateWithCertificates(ca, policy, &trust) == errSecSuccess && SecTrustEvaluateWithError(trust, NULL);
  if (trust) CFRelease(trust);
  CFRelease(policy);
  CFRelease(ca);
  return ok;
}

static void ask(int seq, NSString *cmd, NSDictionary *args) {
  if ([cmd isEqual:@"network"]) return dispatch_async(phone, ^{ reply(seq, net, nil); });
  if ([cmd isEqual:@"caTrusted"]) return reply(seq, @(caTrusted(args[@"pem"])), nil);
  if ([cmd isEqual:@"caRemove"]) return reply(seq, @"In Settings, General → VPN & Device Management: tap Foxhole Relay CA, then Remove Profile.", nil);
  dispatch_async(dispatch_get_main_queue(), ^{
    if ([cmd isEqual:@"copy"]) UIPasteboard.generalPasteboard.string = args[@"text"];
    else if ([cmd isEqual:@"keepAlive"]) keepAlive(![args[@"off"] boolValue] && ![args[@"paused"] boolValue]); // paused, the proxy is off
    else if ([cmd isEqual:@"caInstall"]) { // iOS installs a certificate from Safari: the core serves it there (main.mjs)
      [UIApplication.sharedApplication openURL:[NSURL URLWithString:args[@"url"]] options:@{} completionHandler:nil];
      return reply(seq, @"Safari opens it: tap Allow. Then in Settings, General → VPN & Device Management: install Foxhole Relay CA, and in General → About → Certificate Trust Settings, turn it on. Safari and other apps trust it then.", nil);
    } else return reply(seq, nil, [NSString stringWithFormat:@"iOS can't %@", cmd]);
    reply(seq, nil, nil);
  });
}

// ── The core ─────────────────────────────────────────────────────────────────────────────────────────────────

static void received(const std::string &line) {
  NSData *data = [NSData dataWithBytes:line.data() length:line.size()];
  NSDictionary *msg = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
  if (![msg isKindOfClass:NSDictionary.class]) {
    os_log_error(say, "not JSON from the core: %{public}.200s", line.c_str());
    return;
  }
  if ([msg[@"t"] isEqual:@"ask"]) return ask([msg[@"id"] intValue], msg[@"cmd"], msg[@"args"]);
  [listener emitOnLine:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]];
}

/** node_start with these arguments, in one block (libuv reuses it for the process title), until Node ends. */
static int runNode(const std::vector<std::string> &args) {
  static std::vector<char> block; // stays: Node keeps pointers into it
  size_t size = 0;
  for (auto &s : args) size += s.size() + 1;
  block.assign(size, '\0');
  std::vector<char *> argv;
  char *at = block.data();
  for (auto &s : args) {
    memcpy(at, s.c_str(), s.size());
    argv.push_back(at);
    at += s.size() + 1;
  }
  argv.push_back(nullptr);
  return node_start(static_cast<int>(args.size()), argv.data());
}

/** Node's stdout and stderr, to the system's log a line at a time (Console.app, idevicesyslog). */
static void logOutput() {
  int fds[2];
  if (pipe(fds) != 0) return;
  dup2(fds[1], STDOUT_FILENO);
  dup2(fds[1], STDERR_FILENO);
  close(fds[1]);
  int from = fds[0];
  [[[NSThread alloc] initWithBlock:^{ readLines(from, ^(const std::string &line) { os_log(say, "node: %{public}s", line.c_str()); }); }] start];
}

/** Keeps up with the network the phone is on, the app coming on screen and leaving it, and calls interrupting the silence. */
static void watch() {
  phone = dispatch_queue_create("foxhole.phone", DISPATCH_QUEUE_SERIAL);
  static nw_path_monitor_t monitor = nw_path_monitor_create();
  nw_path_monitor_set_queue(monitor, phone);
  nw_path_monitor_set_update_handler(monitor, ^(nw_path_t path) {
    net = nw_path_get_status(path) != nw_path_status_satisfied ? nil
      : nw_path_uses_interface_type(path, nw_interface_type_wifi) ? @"Wi-Fi"
      : nw_path_uses_interface_type(path, nw_interface_type_cellular) ? @"Mobile data"
      : nw_path_uses_interface_type(path, nw_interface_type_wired) ? @"Ethernet (wired)" : @"Online";
  });
  nw_path_monitor_start(monitor);
  NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
  // the core sends the window its state only while it's on screen
  [center addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:nil usingBlock:^(NSNotification *note) { toCore(@"{\"t\":\"ui\",\"on\":true}"); }];
  [center addObserverForName:UIApplicationDidEnterBackgroundNotification object:nil queue:nil usingBlock:^(NSNotification *note) { toCore(@"{\"t\":\"ui\",\"on\":false}"); }];
  [center addObserverForName:AVAudioSessionInterruptionNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note) {
    if ([note.userInfo[AVAudioSessionInterruptionTypeKey] unsignedIntegerValue] == AVAudioSessionInterruptionTypeEnded) [silence play];
  }];
}

/** Starts the core, once per process: it outlives the window while connected (keepAlive). */
static void startCore() {
  NSString *main = [NSBundle.mainBundle pathForResource:@"main" ofType:@"mjs" inDirectory:@"nodejs-project"];
  if (!main) {
    os_log_error(say, "no nodejs-project in the app: run scripts/prepare.mjs ios before building");
    return;
  }
  // where the core keeps its settings, the sign-in and relay mode's certificate (as ~ on a computer); out of backups
  NSFileManager *files = NSFileManager.defaultManager;
  NSURL *home = [[files URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject URLByAppendingPathComponent:@"home"];
  [files createDirectoryAtURL:home withIntermediateDirectories:YES attributes:nil error:nil];
  [home setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
  setenv("HOME", home.fileSystemRepresentation, 1);
  setenv("TMPDIR", NSTemporaryDirectory().fileSystemRepresentation, 1);
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
    os_log_error(say, "no socket pair: %{public}s", strerror(errno));
    return;
  }
  int one = 1;
  setsockopt(fds[0], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
  mine = fds[0];
  int theirs = fds[1]; // Node's
  logOutput();
  watch();
  std::string script = main.fileSystemRepresentation;
  NSThread *node = [[NSThread alloc] initWithBlock:^{ os_log(say, "Node ended: %d", runNode({"node", script, std::to_string(theirs)})); }];
  node.stackSize = 16 << 20; // V8 wants a deep stack
  [node start];
  [[[NSThread alloc] initWithBlock:^{ readLines(mine, ^(const std::string &line) { received(line); }); }] start];
}

// ── The window's module ──────────────────────────────────────────────────────────────────────────────────────

@implementation FoxholeModule

RCT_EXPORT_MODULE(Foxhole)

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:(const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativeFoxholeSpecJSI>(params);
}

- (void)start
{
  listener = self;
  static dispatch_once_t once;
  dispatch_once(&once, ^{ startCore(); });
}

- (void)send:(NSString *)line
{
  toCore(line);
}

- (NSString *)webView
{
  return @""; // WebKit comes with iOS: the app's lowest iOS is what the window needs
}

- (NSString *)page
{
  return [NSBundle.mainBundle URLForResource:@"index" withExtension:@"html" subdirectory:@"www/renderer"].absoluteString;
}

- (void)moveToBack
{
  // no back button on iOS
}

@end
