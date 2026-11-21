using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace TgProxy {
    static class Wire {
        public static byte[] Hex(string s) { return Enumerable.Range(0,s.Length/2).Select(i=>Convert.ToByte(s.Substring(i*2,2),16)).ToArray(); }
        public static byte[] Join(params byte[][] parts) { var output=new byte[parts.Sum(p=>p.Length)]; int offset=0; foreach(var p in parts) { Buffer.BlockCopy(p,0,output,offset,p.Length); offset+=p.Length; } return output; }
        public static byte[] Random(int count) { var b=new byte[count]; using(var r=RandomNumberGenerator.Create()) r.GetBytes(b); return b; }
        public static byte[] U16(int n) { return new[] { (byte)(n>>8),(byte)n }; }
        public static byte[] Hmac(byte[] key,byte[] data) { using(var h=new HMACSHA256(key)) return h.ComputeHash(data); }
        public static byte[] Read(Stream stream,int n) {
            if(n<1 || n>65535) throw new IOException("Invalid length");
            var b=new byte[n]; int offset=0;
            while(offset<n) { int k=stream.Read(b,offset,n-offset); if(k==0) throw new EndOfStreamException(); offset+=k; }
            return b;
        }
        public static byte[] Record(Stream s,int type) {
            var h=Read(s,5); if(h[0]!=type || h[1]!=3 || h[2]!=3) throw new IOException("Invalid TLS record");
            return Join(h,Read(s,(h[3]<<8)|h[4]));
        }
        public static bool Equal(byte[] a,byte[] b) { if(a.Length!=b.Length) return false; int diff=0; for(int i=0;i<a.Length;i++) diff|=a[i]^b[i]; return diff==0; }
    }
    // AES CTR is used only for the Telegram obfuscated transport; TLS here is MTProxy Fake TLS.
    sealed class AesCtr : IDisposable {
        readonly Aes aes; readonly ICryptoTransform encrypt; readonly byte[] counter,block=new byte[16]; int offset=16;
        public AesCtr(byte[] init,byte[] secret) {
            aes=Aes.Create(); aes.Mode=CipherMode.ECB; aes.Padding=PaddingMode.None;
            using(var sha=SHA256.Create()) aes.Key=sha.ComputeHash(Wire.Join(init.Skip(8).Take(32).ToArray(),secret));
            counter=init.Skip(40).Take(16).ToArray(); encrypt=aes.CreateEncryptor();
        }
        public byte[] Update(byte[] data) {
            var result=new byte[data.Length];
            for(int i=0;i<data.Length;i++) {
                if(offset==16) { encrypt.TransformBlock(counter,0,16,block,0); for(int j=15;j>=0;j--) { counter[j]++; if(counter[j]!=0) break; } offset=0; }
                result[i]=(byte)(data[i]^block[offset++]);
            }
            return result;
        }
        public void Dispose() { encrypt.Dispose(); aes.Dispose(); }
    }
    static class MtProbe {
        static byte[] Ext(int id,byte[] b) { return Wire.Join(Wire.U16(id),Wire.U16(b.Length),b); }
        static byte[] Hello(Proxy p,out byte[] digest) {
            var domain=Encoding.ASCII.GetBytes(p.Domain);
            var ext=Wire.Join(Ext(0,Wire.Join(Wire.U16(domain.Length+3),new byte[]{0},Wire.U16(domain.Length),domain)),
                Ext(10,Wire.Hex("0006001d00170018")),Ext(11,Wire.Hex("0100")),Ext(13,Wire.Hex("00080403080404010503")),
                Ext(43,Wire.Hex("0403040303")),Ext(45,Wire.Hex("0101")),Ext(51,Wire.Join(Wire.Hex("0024001d0020"),Wire.Random(32))),Ext(23,new byte[0]),Ext(65281,new byte[]{0}));
            var prefix=Wire.Join(Wire.Hex("0303"),new byte[32],new byte[]{32},Wire.Random(32),Wire.Hex("0012130113021303c02bc02fc02cc030cca9cca80100"));
            ext=Wire.Join(ext,Ext(21,new byte[Math.Max(0,512-(5+4+prefix.Length+2+ext.Length+4))]));
            var body=Wire.Join(prefix,Wire.U16(ext.Length),ext);
            var hello=Wire.Join(Wire.Hex("160301"),Wire.U16(body.Length+4),new byte[]{1,0},Wire.U16(body.Length),body);
            digest=Wire.Hmac(p.Key,hello);
            var time=BitConverter.GetBytes((int)(DateTime.UtcNow-new DateTime(1970,1,1)).TotalSeconds);
            for(int i=0;i<4;i++) digest[28+i]^=time[i];
            Buffer.BlockCopy(digest,0,hello,11,32); return hello;
        }
        public static long? Check(Proxy p,CancellationToken token) {
            var watch=Stopwatch.StartNew();
            using(var client=new TcpClient())
            using(var cancel=token.Register(()=>client.Close()))
            using(var deadline=new Timer(_=>client.Close(),null,4500,Timeout.Infinite)) {
                try {
                    token.ThrowIfCancellationRequested();
                    var connect=client.ConnectAsync(p.Host,p.Port);
                    // Observe late failures even after the bounded wait returns.
                    connect.ContinueWith(t=>{var ignored=t.Exception;},System.Threading.Tasks.TaskContinuationOptions.OnlyOnFaulted);
                    if(!connect.Wait(1800,token)) return null;
                    client.ReceiveTimeout=2200; client.SendTimeout=2200;
                    using(var stream=client.GetStream()) {
                        bool tls=p.Domain!=null;
                        if(tls) {
                            byte[] digest; var hello=Hello(p,out digest); stream.Write(hello,0,hello.Length);
                            var response=Wire.Join(Wire.Record(stream,22),Wire.Record(stream,20),Wire.Record(stream,23));
                            if(response.Length<43) return null;
                            var serverDigest=response.Skip(11).Take(32).ToArray(); Array.Clear(response,11,32);
                            if(!Wire.Equal(serverDigest,Wire.Hmac(p.Key,Wire.Join(digest,response)))) return null;
                            var change=Wire.Hex("140303000101"); stream.Write(change,0,change.Length);
                        }
                        byte[] init;
                        do { init=Wire.Random(64); } while(init[0]==0xef || init.Skip(4).Take(4).All(x=>x==0) || new[]{"HEAD","POST","GET ","OPTI"}.Contains(Encoding.ASCII.GetString(init,0,4)) || init.Take(4).All(x=>x==0xee || x==0xdd));
                        for(int i=56;i<60;i++) init[i]=p.Padded?(byte)0xdd:(byte)0xef;
                        init[60]=2; init[61]=0;
                        using(var enc=new AesCtr(init,p.Key))
                        using(var dec=new AesCtr(init.Reverse().ToArray(),p.Key)) {
                            var encrypted=enc.Update(init); Buffer.BlockCopy(encrypted,56,init,56,8); Send(stream,tls,init);
                            var nonce=Wire.Random(16); byte[] request;
                            using(var ms=new MemoryStream()) using(var writer=new BinaryWriter(ms)) {
                                writer.Write(0L); writer.Write(((long)(DateTime.UtcNow-new DateTime(1970,1,1)).TotalSeconds)<<32); writer.Write(20); writer.Write(0xbe7e8ef1); writer.Write(nonce); request=ms.ToArray();
                            }
                            byte[] frame;
                            if(p.Padded) { var data=Wire.Join(request,Wire.Random(Wire.Random(1)[0]%16)); frame=Wire.Join(BitConverter.GetBytes(data.Length),data); }
                            else frame=Wire.Join(new byte[]{10},request);
                            Send(stream,tls,enc.Update(frame));
                            var reader=new FrameReader(stream,tls);
                            int length;
                            if(p.Padded) length=BitConverter.ToInt32(dec.Update(reader.Read(4)),0);
                            else { var first=dec.Update(reader.Read(1))[0]; if(first==127) { var b=dec.Update(reader.Read(3)); length=(b[0]|b[1]<<8|b[2]<<16)*4; } else length=first*4; }
                            if(length<76 || length>4096 || !ValidReply(dec.Update(reader.Read(length)),nonce)) return null;
                            return watch.ElapsedMilliseconds;
                        }
                    }
                } catch(Exception e) {
                    if(e is IOException || e is SocketException || e is ObjectDisposedException || e is OperationCanceledException || e is AggregateException || e is InvalidOperationException || e is CryptographicException) return null;
                    throw;
                }
            }
        }
        static void Send(Stream stream,bool tls,byte[] b) { if(tls) { var h=Wire.Join(Wire.Hex("170303"),Wire.U16(b.Length)); stream.Write(h,0,h.Length); } stream.Write(b,0,b.Length); }
        sealed class FrameReader {
            readonly Stream source; readonly bool tls; byte[] record=new byte[0]; int offset;
            public FrameReader(Stream s,bool useTls) { source=s; tls=useTls; }
            public byte[] Read(int n) {
                if(!tls) return Wire.Read(source,n);
                var output=new byte[n]; int pos=0;
                while(pos<n) {
                    if(offset==record.Length) { record=Wire.Record(source,23).Skip(5).ToArray(); offset=0; }
                    int count=Math.Min(n-pos,record.Length-offset); Buffer.BlockCopy(record,offset,output,pos,count); pos+=count; offset+=count;
                }
                return output;
            }
        }
        public static bool ValidReply(byte[] b,byte[] nonce) {
            if(b.Length<76 || nonce.Length!=16 || BitConverter.ToInt64(b,0)!=0) return false;
            int size=BitConverter.ToInt32(b,16);
            return size>=56 && size<=b.Length-20 && size%4==0 && BitConverter.ToInt32(b,20)==0x05162463 && Wire.Equal(b.Skip(24).Take(16).ToArray(),nonce);
        }
    }
}
