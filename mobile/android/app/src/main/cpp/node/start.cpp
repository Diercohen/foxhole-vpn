// Starts Node (libnode.so) in the thread that calls it, until it ends; its stdout and stderr go to logcat.
#include <android/log.h>
#include <jni.h>
#include <pthread.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace node {
int Start(int argc, char* argv[]);  // node.h's, exported by libnode.so
}

/** Writes what comes on the pipe `fd` to logcat, a line at a time. */
static void* toLogcat(void* fd) {
  char buf[4096];
  std::string line;
  for (ssize_t n; (n = read(static_cast<int>(reinterpret_cast<intptr_t>(fd)), buf, sizeof buf)) > 0;) {
    line.append(buf, n);
    for (size_t i; (i = line.find('\n')) != std::string::npos; line.erase(0, i + 1))
      __android_log_write(ANDROID_LOG_INFO, "foxhole-node", line.substr(0, i).c_str());
  }
  return nullptr;
}

extern "C" JNIEXPORT jint JNICALL Java_io_github_diercohen_foxhole_Core_startNode(JNIEnv* env, jobject, jobjectArray args) {
  int pipeFds[2];
  if (pipe(pipeFds) == 0) {
    dup2(pipeFds[1], STDOUT_FILENO);
    dup2(pipeFds[1], STDERR_FILENO);
    close(pipeFds[1]);
    pthread_t t;
    if (pthread_create(&t, nullptr, toLogcat, reinterpret_cast<void*>(static_cast<intptr_t>(pipeFds[0]))) == 0) pthread_detach(t);
  }
  // node::Start takes its arguments one after another in one block (libuv reuses it for the process title)
  std::vector<std::string> strs;
  for (jsize i = 0, n = env->GetArrayLength(args); i < n; i++) {
    auto s = static_cast<jstring>(env->GetObjectArrayElement(args, i));
    const char* c = env->GetStringUTFChars(s, nullptr);
    strs.emplace_back(c);
    env->ReleaseStringUTFChars(s, c);
  }
  size_t size = 0;
  for (auto& s : strs) size += s.size() + 1;
  static std::vector<char> block;  // stays: Node keeps pointers into it
  block.assign(size, '\0');
  std::vector<char*> argv;
  char* at = block.data();
  for (auto& s : strs) {
    memcpy(at, s.c_str(), s.size());
    argv.push_back(at);
    at += s.size() + 1;
  }
  argv.push_back(nullptr);
  return node::Start(static_cast<int>(strs.size()), argv.data());
}
