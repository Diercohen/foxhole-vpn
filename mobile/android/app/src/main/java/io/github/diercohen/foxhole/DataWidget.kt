package io.github.diercohen.foxhole

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.widget.RemoteViews

/** The home screen's widget: the month's data left as a ring with the fox in it, as the window's header has it, and whether Foxhole's on. A tap opens Foxhole. */
class DataWidget : AppWidgetProvider() {
  override fun onUpdate(ctx: Context, manager: AppWidgetManager, ids: IntArray) = manager.updateAppWidget(ids, views(ctx))

  companion object {
    fun redraw(ctx: Context) {
      val manager = AppWidgetManager.getInstance(ctx) ?: return // none on a TV
      val ids = manager.getAppWidgetIds(ComponentName(ctx, DataWidget::class.java))
      if (ids.isNotEmpty()) manager.updateAppWidget(ids, views(ctx))
    }

    private fun views(ctx: Context): RemoteViews {
      val s = Status.read(ctx)
      return RemoteViews(ctx.packageName, R.layout.data_widget).apply {
        setImageViewBitmap(R.id.ring, ring(s.fraction, s.on))
        setTextViewText(R.id.left, s.left.ifEmpty { "Foxhole" })
        val w = Status.words(ctx)
        setTextViewText(R.id.state, w.getString(if (s.busy) R.string.connecting else if (s.on) R.string.on_at else if (s.paused) R.string.paused else R.string.widget_off, s.where))
        setOnClickPendingIntent(R.id.widget, PendingIntent.getActivity(ctx, 0, Intent(ctx, FoxholeActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
      }
    }

    /** What's left of the data over a dim track: green while connected, else the fox's orange; none while it's not known. */
    private fun ring(fraction: Float, on: Boolean): Bitmap {
      val size = 144
      val stroke = 14f
      val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
      val canvas = Canvas(bitmap)
      val box = RectF(stroke / 2, stroke / 2, size - stroke / 2, size - stroke / 2)
      val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = stroke
        strokeCap = Paint.Cap.ROUND
      }
      canvas.drawArc(box, 0f, 360f, false, paint.apply { color = 0x2EFFFFFF })
      if (fraction > 0f) canvas.drawArc(box, -90f, 360f * fraction.coerceAtMost(1f), false, paint.apply { color = if (on) 0xFF2EE6A8.toInt() else 0xFFFF7A1A.toInt() })
      return bitmap
    }
  }
}
