package app.tgproxy.simple

import org.junit.Test
import org.junit.Assert.*

class LiveTest {
    @Test fun githubAndRealProbes() {
        if (System.getenv("TG_LIVE_TEST") != "1") return
        val f=java.io.File.createTempFile("tg-live", ".txt")
        f.delete()
        try {
            val repo=ProxyRepository(f) { error("Live download failed") }
            val proxies=repo.load()
            assertTrue(proxies.isNotEmpty())
            println("LIVE_GITHUB_PARSED=${proxies.size}")
            val results=Selector.check(proxies)
            println("LIVE_HANDSHAKES=${results.size}")
            results.forEach { println("LIVE_OK ${it.proxy.host} ${it.millis}ms") }
            println("LIVE_SELECTED=${Selector.best(results,null)?.host ?: "NONE"}")
        } finally { f.delete() }
    }
}
