package io.github.diercohen.foxhole

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import java.io.File

/**
 * The Quick Settings tile: Foxhole on or off at a tap, as the window's power button does (mobile/node/main.mjs "tile"),
 * the core started for it if need be. What only the window can do opens it instead: signing in, and letting Foxhole be
 * Android's VPN, which whole-system mode needs.
 */
class FoxholeTile : TileService() {
  override fun onStartListening() {
    listening = this
    draw()
  }

  override fun onStopListening() {
    if (listening === this) listening = null
  }

  override fun onClick() {
    val s = Status.read(this)
    if (s.on || s.busy) return Core.send("""{"t":"disconnect"}""") // on: the core is running
    if (!s.signedIn || (wholeSystem() && VpnService.prepare(this) != null)) return openApp()
    Core.start(this)
    Core.send("""{"t":"tile"}""")
    qsTile?.apply {
      state = Tile.STATE_ACTIVE
      if (Build.VERSION.SDK_INT >= 29) subtitle = Status.words(this@FoxholeTile).getString(R.string.connecting) // till the core says (it says once it's tried)
      updateTile()
    }
  }

  /** The mode last picked in the window is whole system (main.mjs MODE: "global", or nothing picked yet). */
  private fun wholeSystem() = File(filesDir, "home/mode").let { !it.isFile || it.readText() == "global" }

  private fun openApp() {
    val open = Intent(this, FoxholeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    if (Build.VERSION.SDK_INT >= 34) startActivityAndCollapse(PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE))
    else @Suppress("DEPRECATION") startActivityAndCollapse(open) // Android 14 refuses an Intent here
  }

  private fun draw() {
    val tile = qsTile ?: return
    val s = Status.read(this)
    tile.state = if (s.on || s.busy) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
    tile.label = "Foxhole"
    val w = Status.words(this)
    if (Build.VERSION.SDK_INT >= 29) tile.subtitle = if (s.on && !s.busy) s.where else w.getString(if (s.busy) R.string.connecting else if (s.paused) R.string.paused else R.string.widget_off)
    tile.updateTile()
  }

  companion object {
    @Volatile private var listening: FoxholeTile? = null // Quick Settings is open: the tile draws at once

    /** Draws the tile again: now while it's shown, else when it's next shown (Android asks it then). */
    fun redraw(ctx: Context) {
      val shown = listening
      if (shown != null) {
        Handler(Looper.getMainLooper()).post { shown.draw() }
        return
      }
      try {
        requestListeningState(ctx, ComponentName(ctx, FoxholeTile::class.java))
      } catch (_: Exception) {
        // no Quick Settings (a TV)
      }
    }
  }
}
