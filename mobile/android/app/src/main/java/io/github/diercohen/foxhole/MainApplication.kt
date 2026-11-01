package io.github.diercohen.foxhole

import android.app.Application
import androidx.appcompat.app.AppCompatDelegate
import com.facebook.react.PackageList
import com.facebook.react.ReactApplication
import com.facebook.react.ReactHost
import com.facebook.react.ReactNativeApplicationEntryPoint.loadReactNative
import com.facebook.react.defaults.DefaultReactHost.getDefaultReactHost

class MainApplication : Application(), ReactApplication {
  override val reactHost: ReactHost by lazy {
    getDefaultReactHost(context = applicationContext, packageList = PackageList(this).packages.apply { add(FoxholePackage()) })
  }

  override fun onCreate() {
    super.onCreate()
    // Foxhole is dark: the system's bars (Android 9's navigation bar is light otherwise), Mozilla's sign-in page too
    AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
    loadReactNative(this)
  }
}
