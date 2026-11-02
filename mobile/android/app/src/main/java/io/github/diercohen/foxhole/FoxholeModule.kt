package io.github.diercohen.foxhole

import android.webkit.WebView
import com.facebook.react.BaseReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfo
import com.facebook.react.module.model.ReactModuleInfoProvider

/** The window's way to the core (specs/NativeFoxhole.ts): its lines both ways. */
class FoxholeModule(context: ReactApplicationContext) : NativeFoxholeSpec(context) {
  private val listener: (String) -> Unit = { emitOnLine(it) }

  override fun getName() = NAME

  override fun start() {
    Core.listener = listener
    Core.start(reactApplicationContext)
  }

  override fun send(line: String) = Core.send(line)

  override fun webView(): String = WebView.getCurrentWebViewPackage()?.let { "${it.packageName} ${it.versionName}" } ?: ""

  override fun page() = "file:///android_asset/www/renderer/index.html" // scripts/prepare.mjs puts it there

  override fun moveToBack() {
    reactApplicationContext.currentActivity?.moveTaskToBack(true)
  }

  override fun invalidate() {
    if (Core.listener === listener) Core.listener = null
    super.invalidate()
  }

  companion object {
    const val NAME = "Foxhole"
  }
}

class FoxholePackage : BaseReactPackage() {
  override fun getModule(name: String, reactContext: ReactApplicationContext): NativeModule? =
    if (name == FoxholeModule.NAME) FoxholeModule(reactContext) else null

  override fun getReactModuleInfoProvider() = ReactModuleInfoProvider {
    mapOf(FoxholeModule.NAME to ReactModuleInfo(FoxholeModule.NAME, FoxholeModule.NAME, false, false, false, true))
  }
}
