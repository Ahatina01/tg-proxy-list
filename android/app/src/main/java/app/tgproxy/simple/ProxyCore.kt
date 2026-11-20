package app.tgproxy.simple

import java.net.URI
import java.net.URLDecoder
import java.util.Base64
import java.util.concurrent.*

data class Proxy(val link: String, val host: String, val port: Int, val key: ByteArray, val domain: String?, val padded: Boolean)
data class ProbeResult(val proxy: Proxy, val millis: Long)

object ProxyParser {
    fun parse(text: String): List<Proxy> = text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.distinct().mapNotNull { line ->
        try {
            val uri = URI(line)
            require(uri.scheme == "https" && uri.host == "t.me" && uri.path == "/proxy" && uri.fragment == null && uri.userInfo == null && uri.port == -1)
            val pairs = (uri.rawQuery ?: "").split('&').map { it.split('=', limit = 2) }
            require(pairs.all { it.size == 2 })
            val params = pairs.map { URLDecoder.decode(it[0], "UTF-8") to URLDecoder.decode(it[1], "UTF-8") }
            require(params.map { it.first }.distinct().size == params.size)
            val map = params.toMap()
            val host = map.getValue("server")
            require(host.length in 1..253 && host.matches(Regex("[a-zA-Z0-9.:-]+")))
            val port = map.getValue("port").toInt()
            require(port in 1..65535)
            val s = map.getValue("secret")
            val secret = if (s.length % 2 == 0 && s.matches(Regex("[0-9a-fA-F]+"))) s.chunked(2).map { it.toInt(16).toByte() }.toByteArray() else Base64.getUrlDecoder().decode(s)
            val tls = secret.size > 17 && secret[0] == 0xee.toByte()
            require(secret.size == 16 || (secret.size == 17 && secret[0] == 0xdd.toByte()) || tls)
            val domain = if (tls) String(secret.copyOfRange(17, secret.size), Charsets.US_ASCII) else null
            require(domain == null || (domain.length in 1..253 && domain.matches(Regex("[a-zA-Z0-9.-]+"))))
            Proxy(line, host, port, if (secret.size == 16) secret else secret.copyOfRange(1,17), domain, secret.size != 16)
        } catch (_: Exception) { null }
    }.take(256).toList()
}

object Selector {
    fun best(results: List<ProbeResult>, previous: String?): Proxy? {
        val alternatives = results.filter { it.proxy.link != previous }
        return (alternatives.ifEmpty { results }).minByOrNull { it.millis }?.proxy
    }
    fun check(proxies: List<Proxy>, probe: (Proxy) -> Long? = { MtProbe.check(it) }): List<ProbeResult> {
        val pool = Executors.newFixedThreadPool(8) { r -> Thread(r, "proxy-probe").apply { isDaemon = true } }
        val completion = ExecutorCompletionService<ProbeResult?>(pool)
        val tasks = proxies.shuffled().map { p -> completion.submit(Callable { probe(p)?.let { ProbeResult(p,it) } }) }
        val results = mutableListOf<ProbeResult>()
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(12)
        try {
            repeat(tasks.size) {
                val remaining = end - System.nanoTime()
                if (remaining <= 0) return results
                val f = completion.poll(remaining, TimeUnit.NANOSECONDS) ?: return results
                try { f.get()?.let { results.add(it) } } catch (_: ExecutionException) { }
            }
        } finally { tasks.forEach { it.cancel(true) }; pool.shutdownNow() }
        return results
    }
}
