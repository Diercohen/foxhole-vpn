package io.github.diercohen.foxhole

import android.content.Context
import android.content.res.Configuration
import org.json.JSONObject
import java.util.Locale

/**
 * What the Quick Settings tile (FoxholeTile) and the home screen's widget (DataWidget) show: whether Foxhole's on and
 * where, and the month's data left. The core tells it as it changes (Phone "status"); it's kept for when the core
 * isn't running, which means it's off.
 */
object Status {
  data class Now(
    val on: Boolean, // connected
    val busy: Boolean, // connecting
    val paused: Boolean, // from the notification, or a network's rule
    val where: String, // the location's name
    val left: String, // "20 GB left", "Unlimited", or "" before it's known
    val fraction: Float, // of the data left, 0 to 1; under 0: not known
    val signedIn: Boolean, // the core can connect without the window
  )

  /** The core is running in this process: what it said last holds. Not, and nothing is on. */
  @Volatile var live = false

  private fun prefs(ctx: Context) = ctx.getSharedPreferences("status", Context.MODE_PRIVATE)

  fun read(ctx: Context): Now =
    prefs(ctx).run {
      Now(
        live && getBoolean("on", false),
        live && getBoolean("busy", false),
        live && getBoolean("paused", false),
        getString("where", "") ?: "",
        getString("left", "") ?: "",
        getFloat("fraction", -1f),
        getBoolean("signedIn", false),
      )
    }

  /** Foxhole's own words (res/values, values-fa) in the language Settings has, whatever the phone's is. */
  fun words(ctx: Context): Context {
    val lang = prefs(ctx).getString("lang", null) ?: return ctx // the core's not said yet: the phone's
    return ctx.createConfigurationContext(Configuration(ctx.resources.configuration).apply { setLocale(Locale.forLanguageTag(lang)) })
  }

  /** The core's word (main.mjs push), kept and shown. */
  fun set(ctx: Context, o: JSONObject) {
    prefs(ctx).edit()
      .putBoolean("on", o.optBoolean("on"))
      .putBoolean("busy", o.optBoolean("busy"))
      .putBoolean("paused", o.optBoolean("paused"))
      .putString("where", o.optString("where"))
      .putString("left", o.optString("left"))
      .putFloat("fraction", o.optDouble("fraction", -1.0).toFloat())
      .putBoolean("signedIn", o.optBoolean("signedIn"))
      .putString("lang", o.optString("lang", "en"))
      .apply()
    FoxholeTile.redraw(ctx)
    DataWidget.redraw(ctx)
  }
}
