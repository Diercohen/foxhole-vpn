package io.github.diercohen.foxhole

import android.content.Context
import android.content.res.AssetManager
import android.os.ParcelFileDescriptor
import android.system.Os
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import org.json.JSONException
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * Foxhole's core: Node, running node/main.mjs (the desktop app's Controller), once per process. It starts with the
 * window and outlives it while connected (FoxholeService keeps the process). A socket pair carries lines of JSON:
 * what the core asks of the phone is answered by Phone, the rest goes to the window (FoxholeModule).
 */
object Core {
  private const val TAG = "foxhole"

  init {
    System.loadLibrary("node")
    System.loadLibrary("foxhole")
  }

  /** node::Start (start.cpp): runs Node with these arguments until it ends. */
  private external fun startNode(args: Array<String>): Int

  private var mine: ParcelFileDescriptor? = null // this side of the socket pair
  private var out: FileOutputStream? = null

  /** The window's, while there's one. */
  @Volatile var listener: ((String) -> Unit)? = null

  @Synchronized
  fun start(context: Context) {
    if (mine != null) return
    val ctx = context.applicationContext
    val project = unpack(ctx)
    // where the core keeps its settings, the sign-in and relay mode's certificate (as ~ on a computer)
    Os.setenv("HOME", File(ctx.filesDir, "home").apply { mkdirs() }.path, true)
    Os.setenv("TMPDIR", ctx.cacheDir.path, true)
    val (here, there) = ParcelFileDescriptor.createSocketPair()
    mine = here
    out = FileOutputStream(here.fileDescriptor)
    val fd = there.detachFd() // Node's from now on
    // V8 wants a deep stack
    Thread(null, { Log.w(TAG, "Node ended: ${startNode(arrayOf("node", File(project, "main.mjs").path, "$fd"))}") }, "node", 16L shl 20).start()
    thread(name = "core-lines") {
      FileInputStream(here.fileDescriptor).bufferedReader().forEachLine { received(ctx, it) }
    }
  }

  fun send(line: String) {
    val o = out ?: return
    synchronized(o) { o.write("$line\n".toByteArray()) }
  }

  fun answer(id: Int, value: Any?) = send(JSONObject().put("t", "answer").put("id", id).put("v", value ?: JSONObject.NULL).toString())

  fun fail(id: Int, error: String) = send(JSONObject().put("t", "answer").put("id", id).put("error", error).toString())

  private fun received(ctx: Context, line: String) {
    val msg = try {
      JSONObject(line)
    } catch (e: JSONException) {
      Log.w(TAG, "not JSON from the core: ${line.take(200)}")
      return
    }
    if (msg.optString("t") == "ask") Phone.ask(ctx, msg.getInt("id"), msg.getString("cmd"), msg.optJSONObject("args") ?: JSONObject())
    else listener?.invoke(line)
  }

  /** The core's files, out of the app's assets into its own folder: again once the app is installed anew or updated. */
  private fun unpack(ctx: Context): File {
    val dir = File(ctx.filesDir, "nodejs-project")
    val stamp = File(ctx.filesDir, "nodejs-project.stamp")
    @Suppress("DEPRECATION") val installed = ctx.packageManager.getPackageInfo(ctx.packageName, 0).lastUpdateTime.toString()
    if (dir.isDirectory && stamp.isFile && stamp.readText() == installed) return dir
    dir.deleteRecursively()
    copy(ctx.assets, "nodejs-project", dir)
    stamp.writeText(installed)
    return dir
  }

  private fun copy(assets: AssetManager, path: String, to: File) {
    val names = assets.list(path).orEmpty()
    if (names.isEmpty()) return assets.open(path).use { from -> to.outputStream().use { from.copyTo(it) } }
    to.mkdirs()
    for (name in names) copy(assets, "$path/$name", File(to, name))
  }
}
