package app.tgproxy.simple

import java.io.*
import java.net.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** A nonce-matched resPQ proves a usable MTProto path, not a logged-in session. */
object MtProbe {
    private val random = SecureRandom()
    private val closer = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "probe-timeout").apply { isDaemon = true } }
    private fun bytes(n: Int) = ByteArray(n).also { random.nextBytes(it) }
    private fun le(n: Int) = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(n).array()
    private fun u16(n: Int) = byteArrayOf((n shr 8).toByte(), n.toByte())
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun hmac(key: ByteArray, data: ByteArray) = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key,"HmacSHA256")); doFinal(data) }
    private fun read(input: InputStream, n: Int): ByteArray {
        require(n in 1..65535)
        val b = ByteArray(n); var p = 0
        while (p < n) { val count = input.read(b,p,n-p); if (count < 0) throw EOFException(); p += count }
        return b
    }
    private fun record(input: InputStream, type: Int): ByteArray {
        val h = read(input,5)
        require((h[0].toInt() and 255) == type && h[1] == 3.toByte() && h[2] == 3.toByte())
        return h + read(input, ((h[3].toInt() and 255) shl 8) or (h[4].toInt() and 255))
    }
    private fun tlsHello(p: Proxy): Pair<ByteArray,ByteArray> {
        fun ext(id: Int, b: ByteArray) = u16(id) + u16(b.size) + b
        val domain = p.domain!!.toByteArray(Charsets.US_ASCII)
        var extensions = ext(0, u16(domain.size + 3) + byteArrayOf(0) + u16(domain.size) + domain) +
            ext(10, hex("0006001d00170018")) + ext(11, hex("0100")) +
            ext(13, hex("00080403080404010503")) + ext(43, hex("0403040303")) +
            ext(45, hex("0101")) + ext(51, hex("0024001d0020") + bytes(32)) + ext(23, byteArrayOf()) + ext(65281, hex("00"))
        val prefix = hex("0303") + ByteArray(32) + byteArrayOf(32) + bytes(32) + hex("0012130113021303c02bc02fc02cc030cca9cca80100")
        val padding = (512 - (5 + 4 + prefix.size + 2 + extensions.size + 4)).coerceAtLeast(0)
        extensions += ext(21, ByteArray(padding))
        val body = prefix + u16(extensions.size) + extensions
        val hello = hex("160301") + u16(body.size + 4) + byteArrayOf(1,0) + u16(body.size) + body
        val digest = hmac(p.key, hello)
        val now = (System.currentTimeMillis()/1000).toInt()
        val t = le(now)
        for (i in 0..3) digest[28+i] = (digest[28+i].toInt() xor t[i].toInt()).toByte()
        digest.copyInto(hello,11)
        return hello to digest
    }
    fun check(p: Proxy): Long? {
        val start = System.nanoTime()
        val socket = Socket()
        val timeout = closer.schedule({ try { socket.close() } catch (_: Exception) {} }, 4500, TimeUnit.MILLISECONDS)
        try {
            socket.soTimeout = 2200
            socket.connect(InetSocketAddress(p.host,p.port), 1800)
            val input = socket.getInputStream(); val output = socket.getOutputStream()
            val tls = p.domain != null
            if (tls) {
                val (hello,digest) = tlsHello(p)
                output.write(hello); output.flush()
                val response = record(input,22) + record(input,20) + record(input,23)
                require(response.size >= 43)
                val serverDigest = response.copyOfRange(11,43)
                response.fill(0,11,43)
                require(MessageDigest.isEqual(serverDigest, hmac(p.key,digest + response)))
                output.write(hex("140303000101"))
            }
            var init: ByteArray
            do { init = bytes(64) } while (init[0] == 0xef.toByte() || init.copyOfRange(4,8).all { it == 0.toByte() } || String(init,0,4,Charsets.ISO_8859_1) in listOf("HEAD","POST","GET ","OPTI") || init.sliceArray(0..3).all { it == 0xee.toByte() || it == 0xdd.toByte() })
            val tag = if (p.padded) 0xdd else 0xef
            for (i in 56..59) init[i] = tag.toByte()
            init[60] = 2; init[61] = 0
            val reverse = init.reversedArray()
            fun cipher(b: ByteArray): Cipher = Cipher.getInstance("AES/CTR/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(b.copyOfRange(8,40) + p.key), "AES"), IvParameterSpec(b.copyOfRange(40,56)))
            }
            val enc = cipher(init); val dec = cipher(reverse)
            val encrypted = enc.update(init)
            encrypted.copyInto(init,56,56,64)
            fun send(b: ByteArray) { if (tls) output.write(hex("170303") + u16(b.size)); output.write(b); output.flush() }
            send(init)
            val nonce = bytes(16)
            val request = ByteBuffer.allocate(40).order(ByteOrder.LITTLE_ENDIAN).putLong(0).putLong((System.currentTimeMillis()/1000) shl 32).putInt(20).putInt(0xbe7e8ef1.toInt()).put(nonce).array()
            val payload = if (p.padded) { val padded = request + bytes(random.nextInt(16)); le(padded.size) + padded } else byteArrayOf(10) + request
            send(enc.update(payload))
            // TLS records may split the encrypted MTProto frame at arbitrary byte boundaries.
            val incoming = if (tls) TlsInput(input) else input
            fun decrypted(n: Int) = dec.update(read(incoming,n))
            val length = if (p.padded) ByteBuffer.wrap(decrypted(4)).order(ByteOrder.LITTLE_ENDIAN).int else {
                val first = decrypted(1)[0].toInt() and 255
                if (first == 127) { val x = decrypted(3); ((x[0].toInt() and 255) or ((x[1].toInt() and 255) shl 8) or ((x[2].toInt() and 255) shl 16))*4 } else first*4
            }
            require(length in 56..4096)
            require(validReply(decrypted(length),nonce))
            return TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start)
        } catch (_: Exception) { return null } finally { timeout.cancel(false); try { socket.close() } catch (_: Exception) {} }
    }
    private class TlsInput(val source: InputStream): InputStream() {
        var buffer = byteArrayOf(); var pos = 0
        override fun read(): Int {
            if (pos == buffer.size) { val r = record(source,23); buffer = r.copyOfRange(5,r.size); pos = 0 }
            return buffer[pos++].toInt() and 255
        }
    }
    fun validReply(b: ByteArray, nonce: ByteArray): Boolean {
        if (b.size < 76 || nonce.size != 16) return false
        val view = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
        if (view.long != 0L) return false
        view.long
        val size = view.int
        if (size < 56 || size > b.size-20 || size % 4 != 0) return false
        if (view.int != 0x05162463) return false
        return MessageDigest.isEqual(b.copyOfRange(24,40),nonce)
    }
}
