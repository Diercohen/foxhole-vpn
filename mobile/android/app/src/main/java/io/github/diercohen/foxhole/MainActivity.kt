package io.github.diercohen.foxhole

import android.content.Intent
import com.facebook.react.ReactActivity
import com.facebook.react.ReactActivityDelegate
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint.fabricEnabled
import com.facebook.react.defaults.DefaultReactActivityDelegate

class MainActivity : ReactActivity() {
  override fun getMainComponentName(): String = "Foxhole"

  override fun createReactActivityDelegate(): ReactActivityDelegate = DefaultReactActivityDelegate(this, mainComponentName, fabricEnabled)

  // The core sends the window its state only while it's on screen
  override fun onResume() {
    super.onResume()
    shown = this
    Phone.resumed(this)
    Core.send("""{"t":"ui","on":true}""")
  }

  override fun onPause() {
    if (shown === this) shown = null
    Core.send("""{"t":"ui","on":false}""")
    super.onPause()
  }

  // the answer to Android's question whether Foxhole may be a VPN (Phone.vpnStart)
  @Suppress("OVERRIDE_DEPRECATION")
  override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    super.onActivityResult(requestCode, resultCode, data)
    if (requestCode == VPN_CONSENT) Phone.consented(resultCode == RESULT_OK)
  }

  // the answer to Android's question about Location, for the Wi-Fi's name (Phone.wifiAccess)
  override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
    super.onRequestPermissionsResult(requestCode, permissions, grantResults)
    if (requestCode == LOCATION) Phone.locationAnswered(permissions, grantResults)
  }

  companion object {
    const val VPN_CONSENT = 0x5650
    const val LOCATION = 0x4c4f
    /** The app on screen, if it is: what asks Android for the VPN, and opens Settings. */
    @Volatile var shown: MainActivity? = null
  }
}
