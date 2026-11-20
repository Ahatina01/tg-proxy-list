package app.tgproxy.simple

import java.io.File
import java.net.HttpURLConnection
import java.net.URL

class ProxyRepository(private val cache: File, private val bundled: () -> String) {
    companion object { const val SOURCE = "https://raw.githubusercontent.com/Ahatina01/tg-proxy-list/main/proxies.txt" }
    fun load(fetch: () -> String = { download() }): List<Proxy> {
        try {
            val text = fetch()
            val parsed = ProxyParser.parse(text)
            require(parsed.isNotEmpty())
            try {
                val temp = File(cache.parentFile, cache.name + ".tmp")
                temp.writeText(text)
                if (!temp.renameTo(cache)) { cache.writeText(text); temp.delete() }
            } catch (_: Exception) { /* A full disk must not discard a downloaded usable list. */ }
            return parsed
        } catch (_: Exception) {
            val saved = try { ProxyParser.parse(cache.readText()) } catch (_: Exception) { emptyList() }
            return saved.ifEmpty { ProxyParser.parse(bundled()) }
        }
    }
    private fun download(): String {
        val c = URL(SOURCE).openConnection() as HttpURLConnection
        c.connectTimeout = 3500; c.readTimeout = 3500; c.useCaches = false
        c.setRequestProperty("Cache-Control", "no-cache, no-store")
        try {
            require(c.responseCode == 200)
            val data = c.inputStream.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                val deadline = System.nanoTime() + 4_000_000_000L
                while (true) {
                    require(System.nanoTime() < deadline)
                    val n = input.read(buffer); if (n < 0) break
                    require(out.size() + n <= 262144); out.write(buffer,0,n)
                }
                out.toByteArray()
            }
            return String(data, Charsets.UTF_8)
        } finally { c.disconnect() }
    }
}
