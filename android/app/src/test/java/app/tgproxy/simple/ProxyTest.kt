package app.tgproxy.simple

import org.junit.Assert.*
import org.junit.Test

class ProxyTest {
    private val link = "https://t.me/proxy?server=example.com&port=443&secret=ee00112233445566778899aabbccddeeff6578616d706c652e636f6d&extra=a%2Bb"
    @Test fun preservesOriginalAndDecodesSecret() {
        val p = ProxyParser.parse(link).single()
        assertEquals(link, p.link)
        assertEquals("example.com", p.domain)
        assertEquals(16, p.key.size)
    }
    @Test fun rejectsMalformedAndWeb() {
        assertTrue(ProxyParser.parse(link.replace("/proxy?", "/webproxy?")).isEmpty())
        assertTrue(ProxyParser.parse(link.replace("443", "70000")).isEmpty())
        assertTrue(ProxyParser.parse(link + "&port=80").isEmpty())
        assertTrue(ProxyParser.parse(link.replace("t.me/", "evil.test/")).isEmpty())
    }
    @Test fun choosesFastestAndAvoidsPreviousWhenPossible() {
        val a = ProxyParser.parse(link).single()
        val b = a.copy(link = link + "&x=1")
        assertEquals(a, Selector.best(listOf(ProbeResult(b, 90), ProbeResult(a, 20)), null))
        assertEquals(b, Selector.best(listOf(ProbeResult(b, 90), ProbeResult(a, 20)), a.link))
        assertNull(Selector.best(emptyList(), null))
        assertEquals(a, Selector.best(listOf(ProbeResult(a, 20)), a.link))
    }
    @Test fun rejectsWrongNonceAndPlainTcpResponse() {
        assertFalse(MtProbe.validReply(ByteArray(80), ByteArray(16)))
        assertFalse(MtProbe.validReply("HTTP/1.1 200 OK".toByteArray(), ByteArray(16)))
    }
    @Test fun repositoryUpdatesAndFallsBack() {
        val dir = java.nio.file.Files.createTempDirectory("proxy-test").toFile()
        try {
            val repository = ProxyRepository(java.io.File(dir,"cache")) { link }
            assertEquals(link, repository.load { error("offline") }.single().link)
            val updated = link + "&v=2"
            assertEquals(updated, repository.load { updated }.single().link)
            assertEquals(updated, repository.load { error("offline") }.single().link)
            assertEquals(updated, repository.load { "broken" }.single().link)
        } finally { dir.deleteRecursively() }
    }
    @Test fun tcpListenerWithoutMtprotoIsRejected() {
        val listener = java.net.ServerSocket(0)
        val server = Thread {
            listener.use { it.accept().use { s -> s.getOutputStream().write("HTTP/1.1 200 OK\r\n\r\n".toByteArray()) } }
        }
        server.start()
        val p = ProxyParser.parse(link).single().copy(host="127.0.0.1",port=listener.localPort,domain=null)
        assertNull(MtProbe.check(p))
        server.join(3000)
    }
    @Test fun validResPqMustMatchNonce() {
        val nonce=ByteArray(16) { it.toByte() }
        val reply=java.nio.ByteBuffer.allocate(84).order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .putLong(0).putLong(1).putInt(64).putInt(0x05162463).put(nonce).array()
        assertTrue(MtProbe.validReply(reply,nonce))
        assertFalse(MtProbe.validReply(reply,ByteArray(16)))
    }
    @Test fun parallelSelectionToleratesFailure() {
        val a=ProxyParser.parse(link).single()
        val b=a.copy(link=link+"&v=2")
        val results=Selector.check(listOf(a,b)) { if (it.link==a.link) null else 42 }
        assertEquals(b,Selector.best(results,null))
    }
}
