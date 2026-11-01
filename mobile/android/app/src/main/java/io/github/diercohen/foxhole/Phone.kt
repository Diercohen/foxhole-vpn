package io.github.diercohen.foxhole

import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.provider.Settings
import android.security.KeyChain
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
  private fun network(ctx: Context): String? {
    val cm = ctx.getSystemService(ConnectivityManager::class.java)
    val caps = cm.getNetworkCapabilities(cm.activeNetwork ?: return null) ?: return null // outside Foxhole's VPN: the real one
    return when {
      caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
      caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Mobile data"
      caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet (wired)"
      else -> "Online"
    }
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

  /** Opens a screen of Settings (or another app's); false if there's no such screen. */
  private fun open(ctx: Context, intent: Intent): Boolean {
    val activity = MainActivity.shown
    if (activity == null) intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    return runCatching { (activity ?: ctx).startActivity(intent) }.isSuccess
  }
}
