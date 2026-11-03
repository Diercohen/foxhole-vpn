package io.github.diercohen.foxhole

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import hev.htproxy.TProxyService
import java.io.File
import kotlin.concurrent.thread

/**
 * Keeps Foxhole running while it's connected, its notification saying so (other apps may be using the proxy), or
 * paused from that notification (it stays, to resume from), and
 * holds Android's VPN in whole-system mode: every app's connections go into a tunnel (hev-socks5-tunnel) that hands
 * them to the proxy, by name (its DNS answers with stand-in addresses), but this app's own, the proxy's way out.
 */
class FoxholeService : VpnService() {
  private var tun: ParcelFileDescriptor? = null

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    running = this
    ServiceCompat.startForeground(this, NOTE_ID, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
    when (val action = intent?.action) {
      VPN_ON -> {
        val (id, port) = intent.getIntExtra("id", 0) to intent.getIntExtra("port", 0)
        val skip = intent.getStringArrayListExtra("skip").orEmpty()
        val only = intent.getStringArrayListExtra("only").orEmpty()
        thread { tunnelOn(id, port, skip, only) }
      }
      PAUSE, RESUME, DISCONNECT -> Core.send("""{"t":"$action"}""") // the notification's buttons: the core does them
    }
    if (intent?.action != VPN_ON) idle()
    return START_NOT_STICKY
  }

  /** Stops once there's nothing to keep running for: disconnected, and no VPN. */
  @Synchronized
  private fun idle() {
    if (note != null || tun != null) return
    ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
    stopSelf()
    running = null
  }

  private fun show() = getSystemService(NotificationManager::class.java).notify(NOTE_ID, notification())

  /**
   * Split tunneling's apps: `skip` stay out of the VPN (direct); `only`, when any, are the only ones in it. An app
   * that's gone since is passed over.
   */
  @Synchronized
  private fun tunnelOn(id: Int, port: Int, skip: List<String>, only: List<String>) {
    try {
      tunnelOff()
      val builder = Builder()
        .setSession("Foxhole")
        .setMtu(8500)
        .addAddress("198.18.0.1", 32)
        .addRoute("0.0.0.0", 0)
        .addAddress("fc00::1", 128) // IPv6 into the tunnel too, or it would go around the VPN
        .addRoute("::", 0)
        .addDnsServer("198.18.0.2") // the tunnel's DNS (mapdns): names go to the proxy as names
        .setConfigureIntent(openApp())
      // the proxy's own connections go out to the VPN servers, or direct: this app is never in it
      // (none of `only` installed: everything in, everything else's way, direct, done by the proxy)
      val allowed = (only - packageName).count { pkg -> installed { builder.addAllowedApplication(pkg) } }
      if (allowed == 0) for (pkg in skip + packageName) installed { builder.addDisallowedApplication(pkg) }
      if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false) // as metered as the network under it (Android 10+)
      val fd = builder.establish() ?: error("Android didn't let Foxhole start its VPN")
      val config = File(filesDir, "tunnel.yml").apply { writeText(tunnelConfig(port)) }
      // the tunnel uses the descriptor but leaves closing it to us (tunnelOff)
      if (!TProxyService.TProxyStartService(config.path, fd.fd)) {
        fd.close()
        error("the tunnel didn't start")
      }
      Thread.sleep(300)
      if (!TProxyService.TProxyIsRunning()) { // e.g. its settings refused: it says why in the log
        TProxyService.TProxyStopService()
        fd.close()
        error("the tunnel stopped at once")
      }
      tun = fd
      show()
      Core.answer(id, null)
    } catch (e: Exception) {
      Log.w("foxhole", "VPN: $e")
      Core.fail(id, e.message ?: "$e")
      idle()
    }
  }

  /** Runs `add` for an app, false if it isn't installed (any more). */
  private fun installed(add: () -> Unit) =
    try {
      add()
      true
    } catch (_: PackageManager.NameNotFoundException) {
      false
    }

  @Synchronized
  private fun tunnelOff() {
    val fd = tun ?: return
    tun = null
    TProxyService.TProxyStopService()
    fd.close()
  }

  /** Android took the VPN away (the user, or another VPN app): the proxy stays, the core is told. */
  override fun onRevoke() {
    tunnelOff()
    Core.send("""{"t":"vpnStopped"}""")
    show()
    idle()
  }

  override fun onDestroy() {
    tunnelOff()
    if (running === this) running = null
    super.onDestroy()
  }

  private fun openApp() =
    PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_IMMUTABLE)

  private fun notification(): Notification {
    getSystemService(NotificationManager::class.java)
      .createNotificationChannel(NotificationChannel(CHANNEL, "Connection", NotificationManager.IMPORTANCE_LOW))
    val (title, text, paused) = note ?: Triple("Foxhole", "Starting…", false)
    val button = { action: String -> PendingIntent.getService(this, 1, Intent(this, FoxholeService::class.java).setAction(action), PendingIntent.FLAG_IMMUTABLE) }
    return NotificationCompat.Builder(this, CHANNEL)
      .setSmallIcon(R.drawable.ic_notify)
      .setColor(0xFFFF7A1A.toInt())
      .setContentTitle(title)
      .setContentText(text)
      .setOngoing(true)
      .setShowWhen(false)
      .setContentIntent(openApp())
      .addAction(0, if (paused) "Resume" else "Pause", button(if (paused) RESUME else PAUSE))
      .addAction(0, "Disconnect", button(DISCONNECT))
      .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
      .build()
  }

  companion object {
    private const val CHANNEL = "connection"
    private const val NOTE_ID = 1
    private const val VPN_ON = "vpn-on"
    private const val DISCONNECT = "disconnect"
    private const val PAUSE = "pause"
    private const val RESUME = "resume"

    @Volatile private var running: FoxholeService? = null
    /** The notification's title, text and whether it's paused (Resume in place of Pause); null when not connected or paused. */
    @Volatile private var note: Triple<String, String, Boolean>? = null

    /** Connected or paused (`what`: the notification's title, text and whether paused), or neither. */
    fun keep(ctx: Context, what: Triple<String, String, Boolean>?) {
      note = what
      val service = running
      when {
        service == null && what != null -> ContextCompat.startForegroundService(ctx, Intent(ctx, FoxholeService::class.java))
        service != null && what != null -> service.show()
        service != null -> service.idle()
      }
    }

    /** Whole-system mode on, through the proxy on `port` (apps: see tunnelOn); answers the core's ask `id` once it's up (or not). */
    fun vpnOn(ctx: Context, id: Int, port: Int, skip: ArrayList<String>, only: ArrayList<String>) =
      ContextCompat.startForegroundService(
        ctx,
        Intent(ctx, FoxholeService::class.java).setAction(VPN_ON).putExtra("id", id).putExtra("port", port)
          .putStringArrayListExtra("skip", skip).putStringArrayListExtra("only", only),
      )

    fun vpnOff() {
      running?.apply {
        tunnelOff()
        show()
      }
    }

    /** hev-socks5-tunnel's settings: TCP to the proxy over SOCKS5, DNS answered in the tunnel itself. */
    private fun tunnelConfig(port: Int) = """
      |tunnel:
      |  mtu: 8500
      |  ipv4: 198.18.0.1
      |  ipv6: 'fc00::1'
      |socks5:
      |  address: 127.0.0.1
      |  port: $port
      |mapdns:
      |  address: 198.18.0.2
      |  port: 53
      |  network: 100.64.0.0
      |  netmask: 255.192.0.0
      |  cache-size: 10000
      |misc:
      |  task-stack-size: 81920
      |  log-file: stderr
      |  log-level: warn
      |""".trimMargin()
  }
}
