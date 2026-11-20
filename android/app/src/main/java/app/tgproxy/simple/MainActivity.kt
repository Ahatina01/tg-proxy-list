package app.tgproxy.simple

import android.app.Activity
import android.content.Intent
import android.content.ActivityNotFoundException
import android.net.Uri
import android.os.Bundle
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.widget.*
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.Future

class MainActivity : Activity() {
    private lateinit var button: Button
    private lateinit var status: TextView
    private val worker = Executors.newSingleThreadExecutor()
    private var task: Future<*>? = null
    private var pending: Proxy? = null
    private var resumed = false
    private var handedOff = false
    private val prefs by lazy { getSharedPreferences("selection", MODE_PRIVATE) }
    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = Color.rgb(11,17,29)
        window.navigationBarColor = Color.rgb(11,17,29)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER
            setPadding(dp(28),dp(32),dp(28),dp(32))
            background = GradientDrawable(GradientDrawable.Orientation.TL_BR, intArrayOf(Color.rgb(17,31,51),Color.rgb(8,13,23)))
            setOnApplyWindowInsetsListener { v, i -> v.setPadding(dp(28),dp(32)+i.systemWindowInsetTop,dp(28),dp(32)+i.systemWindowInsetBottom); i }
        }
        root.addView(ImageView(this).apply { setImageResource(app.tgproxy.simple.R.drawable.ic_logo); contentDescription = null }, LinearLayout.LayoutParams(dp(84),dp(84)).apply { bottomMargin = dp(24) })
        root.addView(TextView(this).apply { text="TG Proxy"; textSize=34f; setTextColor(Color.WHITE); typeface=Typeface.create("sans-serif-medium",Typeface.NORMAL); gravity=Gravity.CENTER }, LinearLayout.LayoutParams(-1,-2))
        button = Button(this).apply {
            text="Подключить"; textSize=19f; isAllCaps=false; setTextColor(Color.WHITE)
            background = android.graphics.drawable.RippleDrawable(android.content.res.ColorStateList.valueOf(0x44ffffff),GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT,intArrayOf(0xff1679ef.toInt(),0xff329cff.toInt())).apply { cornerRadius=dp(24).toFloat() },null)
            elevation=dp(8).toFloat(); setOnClickListener { connect() }
        }
        root.addView(button,LinearLayout.LayoutParams(-1,dp(68)).apply { topMargin=dp(56); bottomMargin=dp(24) })
        status=TextView(this).apply { text="Прокси для вашего Telegram"; textSize=14f; gravity=Gravity.CENTER; setTextColor(0xff9bacc3.toInt()); accessibilityLiveRegion=View.ACCESSIBILITY_LIVE_REGION_POLITE; minHeight=dp(60) }
        root.addView(status,LinearLayout.LayoutParams(-1,-2))
        setContentView(root)
    }
    private fun connect() {
        if (task?.isDone == false) return
        button.isEnabled=false; button.alpha=0.65f; status.text="Поиск прокси…"
        val previous=prefs.getString("previous",null)
        task=worker.submit {
            try {
                val repository=ProxyRepository(File(filesDir,"proxies.txt")) { assets.open("proxies.txt").bufferedReader().use { it.readText() } }
                val best=Selector.best(Selector.check(repository.load()),previous)
                runOnUiThread {
                    if (isDestroyed || isFinishing) return@runOnUiThread
                    button.isEnabled=true; button.alpha=1f
                    if (best == null) status.text="Нет доступных прокси. Попробуйте ещё раз"
                    else if (resumed) openTelegram(best) else { pending=best; status.text="Прокси найден" }
                }
            } catch (_: Exception) {
                runOnUiThread { if (!isDestroyed) { button.isEnabled=true; button.alpha=1f; status.text="Ошибка подключения" } }
            }
        }
    }
    private fun openTelegram(p: Proxy) {
        status.text="Открываем Telegram…"
        for (pkg in listOf("org.telegram.messenger","org.telegram.messenger.web")) {
            val intent=Intent(Intent.ACTION_VIEW,Uri.parse(p.link)).setPackage(pkg)
            if (intent.resolveActivity(packageManager)==null) continue
            try {
                startActivity(intent)
                prefs.edit().putString("previous",p.link).apply()
                handedOff=true
                return
            } catch (_: ActivityNotFoundException) { } catch (_: SecurityException) { }
        }
        status.text="Установите официальный Telegram"
    }
    override fun onResume() {
        super.onResume(); resumed=true
        if (handedOff) { status.text="Подтвердите подключение в Telegram"; handedOff=false }
        pending?.let { pending=null; openTelegram(it) }
    }
    override fun onPause() { resumed=false; super.onPause() }
    override fun onDestroy() { task?.cancel(true); worker.shutdownNow(); super.onDestroy() }
}
