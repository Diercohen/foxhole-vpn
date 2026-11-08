package io.github.diercohen.foxhole

import android.app.Activity
import android.app.ActivityManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

/**
 * Disguise mode (Settings → Look like a calculator), for a phone that may be searched: the launcher has a calculator
 * that works as one (CalculatorActivity) in Foxhole's place, and its code, then =, opens Foxhole. Android's own
 * Settings still list Foxhole.
 */
object Disguise {
  private const val FOXHOLE = "io.github.diercohen.foxhole.MainActivity" // the launcher's Foxhole: an alias of FoxholeActivity

  private fun prefs(ctx: Context) = ctx.getSharedPreferences("disguise", Context.MODE_PRIVATE)

  /** The calculator's code that opens Foxhole; null: not disguised. */
  fun code(ctx: Context): String? = prefs(ctx).getString("code", null)

  /** Disguised, opened with `code` (4 to 12 digits); or Foxhole again (null). The launcher follows once the window leaves the screen (apply). */
  fun set(ctx: Context, code: String?) {
    require(code == null || Regex("""\d{4,12}""").matches(code)) { "The code is 4 to 12 digits" }
    prefs(ctx).edit().putString("code", code).commit()
    FoxholeActivity.shown?.let(::recents)
  }

  /**
   * The launcher's entry as the code has it: the calculator while there's one, else Foxhole. Not while the window's
   * on screen: Android closes a window the launcher opened as its entry goes.
   */
  fun apply(ctx: Context) {
    val pm = ctx.packageManager
    val calculator = ComponentName(ctx, CalculatorActivity::class.java)
    val on = code(ctx) != null
    if ((pm.getComponentEnabledSetting(calculator) == PackageManager.COMPONENT_ENABLED_STATE_ENABLED) == on) return // as it is
    fun turn(c: ComponentName, state: Int) = pm.setComponentEnabledSetting(c, state, PackageManager.DONT_KILL_APP)
    val foxhole = ComponentName(ctx.packageName, FOXHOLE)
    // the new one first: the launcher always has one of them
    if (on) {
      turn(calculator, PackageManager.COMPONENT_ENABLED_STATE_ENABLED)
      turn(foxhole, PackageManager.COMPONENT_ENABLED_STATE_DISABLED)
    } else {
      turn(foxhole, PackageManager.COMPONENT_ENABLED_STATE_DEFAULT) // as the manifest has them
      turn(calculator, PackageManager.COMPONENT_ENABLED_STATE_DEFAULT)
    }
  }

  /** The window out of Recents while disguised, where it would show Foxhole: it's opened from the calculator again. */
  fun recents(window: Activity) {
    val hide = code(window) != null
    for (task in window.getSystemService(ActivityManager::class.java).appTasks) {
      runCatching { // a task that's just gone
        val info = task.taskInfo ?: return@runCatching
        @Suppress("DEPRECATION") val id = if (Build.VERSION.SDK_INT >= 29) info.taskId else info.persistentId
        if (id == window.taskId) task.setExcludeFromRecents(hide)
      }
    }
  }
}
