package io.github.diercohen.foxhole

import android.Manifest
import android.app.UiModeManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.VpnService
import android.location.LocationManager
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.provider.Settings
import android.security.KeyChain
import androidx.core.content.FileProvider
import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import org.json.JSONObject

/** What the core asks of the phone (node/main.mjs `ask`), each answered by Core.answer or Core.fail. */
object Phone {
  private val main = Handler(Looper.getMainLooper())
  private var consent: ((Boolean) -> Unit)? = null // waits for Android's question whether Foxhole may be a VPN

  fun ask(ctx: Context, id: Int, cmd: String, args: JSONObject) {
    try {
      when (cmd) {
        "copy" -> main.post {
          ctx.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("Foxhole", args.getString("text")))
          Core.answer(id, null)
        }
        "network" -> Core.answer(id, network(ctx))
        "wifiAccess" -> main.post { wifiAccess(ctx, id) }
        "device" -> Core.answer(id, JSONObject().put("tv", isTv(ctx)).put("name", deviceName(ctx)))
        "keepAlive" -> {
          FoxholeService.keep(ctx, if (args.optBoolean("off")) null else Triple(args.getString("title"), args.getString("text"), args.optBoolean("paused")))
          Core.answer(id, null)
        }
        "vpnStart" -> vpnStart(ctx, id, args.getInt("port"))
        "vpnStop" -> {
          FoxholeService.vpnOff()
          Core.answer(id, null)
        }
        "caTrusted" -> Core.answer(id, caTrusted(args.getString("pem")))
        "caInstall" -> main.post { reply(id) { caInstall(ctx, args.getString("pem")) } }
        "caRemove" -> main.post { reply(id) { caRemove(ctx) } }
        "apkCheck" -> Core.answer(id, apkCheck(ctx, args.getString("path"), args.getString("version")))
        "apkInstall" -> main.post { reply(id) { apkInstall(ctx, File(args.getString("path"))) } }
        else -> Core.fail(id, "Android can't $cmd")
      }
    } catch (e: Exception) {
      Core.fail(id, e.message ?: "$e")
    }
  }

  private fun reply(id: Int, what: () -> Any?) =
    try {
      Core.answer(id, what())
    } catch (e: Exception) {
      Core.fail(id, e.message ?: "$e")
    }

  /** What the phone is online through, as the window's Network card says it; null offline. */
  /** A TV (Android TV, Google TV): its window works by remote, and it signs in from another device. */
  fun isTv(ctx: Context): Boolean =
    ctx.getSystemService(UiModeManager::class.java).currentModeType == Configuration.UI_MODE_TYPE_TELEVISION ||
      ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_LEANBACK)

  /** The name the user gave this device (Settings → About), else its model: shown on the other device. */
  private fun deviceName(ctx: Context): String =
    Settings.Global.getString(ctx.contentResolver, "device_name")?.takeIf { it.isNotBlank() } ?: Build.MODEL

  private fun network(ctx: Context): String? {
    val cm = ctx.getSystemService(ConnectivityManager::class.java)
    val caps = cm.getNetworkCapabilities(cm.activeNetwork ?: return null) ?: return null // outside Foxhole's VPN: the real one
    return when {
      caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi · ${wifiName(ctx) ?: "name hidden"}"
      caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Mobile data"
      caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet (wired)"
      else -> "Online"
    }
  }

  // ── The Wi-Fi's name: Android shows it only to apps allowed precise Location, with Location on (it can tell where
  //    you are). Asked for only when the user chooses to see it, having been told why (app.js wifi-modal). ──────────

  private const val FINE = Manifest.permission.ACCESS_FINE_LOCATION
  private var located: ((Boolean, Boolean) -> Unit)? = null // waits for Android's answer: precise, approximate

  /** The connected Wi-Fi's name, or null where Android won't tell (not allowed, or Location off). */
  private fun wifiName(ctx: Context): String? {
    if (ctx.checkSelfPermission(FINE) != PackageManager.PERMISSION_GRANTED) return null
    @Suppress("DEPRECATION") // its replacement (a network callback's WifiInfo) tells the same, asynchronously
    val ssid = ctx.applicationContext.getSystemService(WifiManager::class.java).connectionInfo?.ssid ?: return null
    return ssid.removeSurrounding("\"").takeUnless { it.isBlank() || it == WifiManager.UNKNOWN_SSID }
  }

  /**
   * Asks Android's question (once; denied twice, Android stops asking, so Foxhole's own settings page opens instead),
   * then has Location turned on. Answers "allowed", "denied", "approximate" (precise needed), or "opened" (Settings is
   * on screen, to turn it on there).
   */
  private fun wifiAccess(ctx: Context, id: Int) {
    val activity = MainActivity.shown ?: return Core.fail(id, "open Foxhole to allow it")
    val prefs = ctx.getSharedPreferences("foxhole", Context.MODE_PRIVATE)
    fun open(action: String, data: Uri? = null) =
      try {
        activity.startActivity(Intent(action, data))
        Core.answer(id, "opened")
      } catch (e: android.content.ActivityNotFoundException) {
        Core.fail(id, "This device has no Location settings to turn it on in.")
      }
    fun locationOn() =
      if (ctx.getSystemService(LocationManager::class.java).isLocationEnabled) Core.answer(id, "allowed")
      else open(Settings.ACTION_LOCATION_SOURCE_SETTINGS)
    if (activity.checkSelfPermission(FINE) == PackageManager.PERMISSION_GRANTED) return locationOn()
    if (prefs.getBoolean("locationAsked", false) && !activity.shouldShowRequestPermissionRationale(FINE))
      return open(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", ctx.packageName, null))
    prefs.edit().putBoolean("locationAsked", true).apply()
    located = { precise, approximate ->
      if (precise) locationOn() else Core.answer(id, if (approximate) "approximate" else "denied")
    }
    activity.requestPermissions(arrayOf(FINE, Manifest.permission.ACCESS_COARSE_LOCATION), MainActivity.LOCATION)
  }

  /** Android's answer (MainActivity). */
  fun locationAnswered(permissions: Array<out String>, results: IntArray) {
    val granted = permissions.filterIndexed { i, _ -> results.getOrNull(i) == PackageManager.PERMISSION_GRANTED }
    located?.invoke(FINE in granted, Manifest.permission.ACCESS_COARSE_LOCATION in granted)
    located = null
  }

  // ── Whole-system mode: Android asks the user once whether Foxhole may be a VPN ──────────────────────────────

  private fun vpnStart(ctx: Context, id: Int, port: Int) {
    val question = VpnService.prepare(ctx) ?: return FoxholeService.vpnOn(ctx, id, port)
    val activity = MainActivity.shown ?: return Core.fail(id, "open Foxhole to allow its VPN")
    consent = { ok -> if (ok) FoxholeService.vpnOn(ctx, id, port) else Core.fail(id, "Android's VPN wasn't allowed") }
    @Suppress("DEPRECATION") main.post { activity.startActivityForResult(question, MainActivity.VPN_CONSENT) }
  }

  fun consented(ok: Boolean) {
    consent?.invoke(ok)
    consent = null
  }

  // ── Relay mode's certificate: in Android's store of the user's own ─────────────────────────────────────────

  private const val CA_FILE = "foxhole-relay-ca.crt"

  private fun caTrusted(pem: String): Boolean {
    val ca = CertificateFactory.getInstance("X.509").generateCertificate(pem.byteInputStream())
    val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
    return store.aliases().asSequence().any { it.startsWith("user:") && store.getCertificate(it) == ca }
  }

  /**
   * Android 9 and 10: their certificate installer, opened with it. Later ones install a CA only in Settings: it's saved
   * in Downloads, and Settings opened. What's left to do.
   */
  private fun caInstall(ctx: Context, pem: String): String {
    if (Build.VERSION.SDK_INT < 30) {
      val ca = CertificateFactory.getInstance("X.509").generateCertificate(pem.byteInputStream())
      val install = KeyChain.createInstallIntent().putExtra(KeyChain.EXTRA_CERTIFICATE, ca.encoded).putExtra(KeyChain.EXTRA_NAME, "Foxhole Relay CA")
      if (!open(ctx, install)) error("Android's certificate installer didn't open")
      return "Android asks you to name it: tap OK (it may ask you to set a screen lock first). Chrome trusts it then."
    }
    val files = ctx.contentResolver
    val name = MediaStore.MediaColumns.DISPLAY_NAME
    // a copy saved before goes, or Android would name this one "… (1)"
    runCatching { files.delete(MediaStore.Downloads.EXTERNAL_CONTENT_URI, "$name = ?", arrayOf(CA_FILE)) }
    val uri = files.insert(
      MediaStore.Downloads.EXTERNAL_CONTENT_URI,
      ContentValues().apply {
        put(name, CA_FILE)
        put(MediaStore.MediaColumns.MIME_TYPE, "application/x-x509-ca-cert")
      },
    ) ?: error("couldn't save it in Downloads")
    files.openOutputStream(uri)!!.use { it.write(pem.toByteArray()) }
    open(ctx, Intent(Settings.ACTION_SECURITY_SETTINGS))
    return "Saved as $CA_FILE in Downloads. In Settings, search for “CA certificate”, open it, tap Install anyway, then pick that file. Chrome trusts it then."
  }

  private fun caRemove(ctx: Context): String {
    if (!open(ctx, Intent("com.android.settings.TRUSTED_CREDENTIALS_USER"))) open(ctx, Intent(Settings.ACTION_SECURITY_SETTINGS))
    return "In Settings, open Trusted credentials (search for it), then User: tap Foxhole Relay CA, then Remove."
  }

  // ── An update: the APK the core downloaded (gui/updater.js), to Android's installer ───────────────────────────

  private var waitingApk: File? = null // for Android's leave to install apps: opened once it's given (resumed)

  /** It's this app, the version expected, signed with this app's key: Android would refuse it otherwise, after asking. */
  private fun apkCheck(ctx: Context, path: String, version: String): Any? {
    @Suppress("DEPRECATION") val flags = PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_SIGNATURES
    val pm = ctx.packageManager
    val apk = pm.getPackageArchiveInfo(path, flags) ?: error("the download isn't an Android app")
    if (apk.packageName != ctx.packageName) error("the download isn't Foxhole")
    if (apk.versionName != version) error("the download isn't version $version")
    if (signers(apk) != signers(pm.getPackageInfo(ctx.packageName, flags))) {
      error("it's signed with another key than this copy, so Android won't install it over this one: uninstall Foxhole first")
    }
    return null
  }

  @Suppress("DEPRECATION")
  private fun signers(info: PackageInfo) = (info.signingInfo?.apkContentsSigners ?: info.signatures).orEmpty().map { it.toCharsString() }.toSet()

  /** Android's installer, with the APK; first, once, Settings to let Foxhole install apps (back from there, resumed() opens it). */
  private fun apkInstall(ctx: Context, apk: File): Any? {
    if (!ctx.packageManager.canRequestPackageInstalls()) {
      waitingApk = apk
      if (!open(ctx, Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${ctx.packageName}")))) error("Settings didn't open")
      return null
    }
    val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.updates", apk) // res/xml/updates.xml
    val install = Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    if (!open(ctx, install)) error("Android's installer didn't open")
    return null
  }

  /** The app is on screen again (MainActivity): back from Settings with the leave to install, the update's installer. */
  fun resumed(ctx: Context) {
    val apk = waitingApk ?: return
    if (!ctx.packageManager.canRequestPackageInstalls()) return
    waitingApk = null
    runCatching { apkInstall(ctx, apk) }
  }

  /** Opens a screen of Settings (or another app's); false if there's no such screen. */
  private fun open(ctx: Context, intent: Intent): Boolean {
    val activity = MainActivity.shown
    if (activity == null) intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    return runCatching { (activity ?: ctx).startActivity(intent) }.isSuccess
  }
}
