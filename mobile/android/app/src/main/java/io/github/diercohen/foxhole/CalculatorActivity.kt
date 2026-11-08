package io.github.diercohen.foxhole

import android.app.Activity
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.widget.LinearLayout
import android.widget.TextView
import java.math.BigDecimal
import java.math.MathContext

/**
 * Disguise mode's face (Disguise.kt): in the launcher in Foxhole's place, a calculator that works as one. Its code
 * typed in, then =, opens Foxhole instead of a result.
 */
class CalculatorActivity : Activity() {
  private var input = "" // as typed: digits, ".", "%", and + − × ÷ between numbers
  private var fresh = false // a result is shown: a digit starts anew, an operator goes on from it
  private lateinit var screen: TextView

  override fun onCreate(state: Bundle?) {
    super.onCreate(state)
    if (Disguise.code(this) == null) return foxhole() // Foxhole's storage was cleared, the code with it
    input = state?.getString("input") ?: ""
    val dp = resources.displayMetrics.density
    fun px(v: Int) = (v * dp).toInt()
    screen = TextView(this).apply {
      gravity = Gravity.END or Gravity.BOTTOM
      maxLines = 1
      setTextColor(0xFFF3F4F6.toInt())
      setAutoSizeTextTypeUniformWithConfiguration(28, 72, 2, TypedValue.COMPLEX_UNIT_SP)
      setPadding(px(28), 0, px(28), px(20))
    }
    val keys = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(px(10), 0, px(10), px(10))
      for (row in KEYS) {
        addView(LinearLayout(context).apply {
          for (k in row) addView(key(k, dp), LinearLayout.LayoutParams(0, MATCH_PARENT, 1f).apply { setMargins(px(5), px(5), px(5), px(5)) })
        }, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
      }
    }
    setContentView(LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      fitsSystemWindows = true // clear of the status and navigation bars, which Android 15+ draws over the window
      setBackgroundColor(0xFF111215.toInt())
      addView(screen, LinearLayout.LayoutParams(MATCH_PARENT, 0, 2f))
      addView(keys, LinearLayout.LayoutParams(MATCH_PARENT, 0, 3f))
    })
    show()
  }

  override fun onSaveInstanceState(out: Bundle) {
    super.onSaveInstanceState(out)
    out.putString("input", input) // turned sideways, the sum stays
  }

  private fun key(k: String, dp: Float) = TextView(this).apply {
    text = k
    gravity = Gravity.CENTER
    textSize = 26f
    setTextColor((if (k == "=") 0xFF1A1206 else if (k in OPS) 0xFFFFA24D else 0xFFF3F4F6).toInt())
    val face = if (k == "=") 0xFFFF8A1F else if (k in OPS || k in "C⌫%") 0xFF33363D else 0xFF1F2126
    background = RippleDrawable(ColorStateList.valueOf(0x40FFFFFF), GradientDrawable().apply { cornerRadius = 24 * dp; setColor(face.toInt()) }, null)
    setOnClickListener { press(k) }
  }

  private fun press(k: String) {
    if (fresh && (k[0].isDigit() || k == ".")) input = ""
    fresh = false
    val last = input.lastOrNull()
    when (k) {
      "C" -> input = ""
      "⌫" -> input = input.dropLast(1)
      "=" -> return equals()
      "%" -> if (last != null && (last.isDigit() || last == '.')) input += k
      "." -> if (last != '%' && '.' !in input.takeLastWhile { it.isDigit() || it == '.' }) input += k
      "+", "−", "×", "÷" -> input = when {
        input.isEmpty() || input == "−" -> if (k == "−") k else "" // only a minus can start a sum
        input.last() in OPS -> input.dropLast(1) + k // the operator changed
        else -> input + k
      }
      else -> if (last != '%') input += k // a digit, or 00
    }
    show()
  }

  private fun equals() {
    if (input == Disguise.code(this)) return foxhole()
    val result = evaluate(input.trimEnd(*OPS.toCharArray()))?.let(::plain)
    input = result?.takeUnless { 'E' in it } ?: "" // an exponent can't be typed on
    fresh = true
    screen.text = result ?: "Error"
  }

  private fun show() {
    screen.text = input.ifEmpty { "0" }
  }

  /** The window, the calculator gone from Recents (what was typed with it). */
  private fun foxhole() {
    Disguise.apply(this) // no code (Foxhole's storage was cleared): Foxhole in the launcher again
    startActivity(Intent(this, FoxholeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    finishAndRemoveTask()
  }

  private companion object {
    const val OPS = "+−×÷"
    val KEYS = listOf(
      listOf("C", "⌫", "%", "÷"),
      listOf("7", "8", "9", "×"),
      listOf("4", "5", "6", "−"),
      listOf("1", "2", "3", "+"),
      listOf("00", "0", ".", "="),
    )

    /** `e`'s value: × and ÷ before + and −, a % a hundredth; null if it isn't one (a lone "."), or divides by 0. */
    fun evaluate(e: String): BigDecimal? =
      try {
        Regex("[+−]?[^+−]+").findAll(e).fold(BigDecimal.ZERO) { sum, term ->
          val product = Regex("[×÷]?[^×÷]+").findAll(term.value.trimStart('+', '−')).fold(BigDecimal.ONE) { p, f ->
            val n = f.value.trimStart('×', '÷').let { if (it.endsWith('%')) BigDecimal(it.dropLast(1)).movePointLeft(2) else BigDecimal(it) }
            if (f.value[0] == '÷') p.divide(n, MathContext.DECIMAL64) else p.multiply(n)
          }
          if (term.value[0] == '−') sum - product else sum + product
        }
      } catch (_: ArithmeticException) {
        null
      } catch (_: NumberFormatException) {
        null
      }

    /** As calculators show it: 12 digits at most, with an exponent only past them. */
    fun plain(v: BigDecimal): String {
      val r = v.round(MathContext(12)).stripTrailingZeros()
      val exponent = r.precision() - r.scale() - 1
      return (if (exponent in -6..11) r.toPlainString() else r.toString()).replace('-', '−')
    }
  }
}
