using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace TgProxy {
    static class Tests {
        static int count;
        const string Link = "https://t.me/proxy?server=example.com&port=443&secret=ee00112233445566778899aabbccddeeff6578616d706c652e636f6d&extra=a%2Bb";
        static void Check(bool value, string name) { if (!value) throw new Exception(name); Console.WriteLine("PASS " + name); count++; }
        static int Main(string[] args) {
            try {
                var a=ProxyParser.Parse(Link).Single();
                Check(a.Link==Link && a.Domain=="example.com" && a.Key.Length==16,"Parse/preserve link");
                Check(a.DeepLink=="tg://proxy?"+Link.Split('?')[1],"Preserve query in tg link");
                string launched=null;
                Check(!TelegramLauncher.Open(a,()=>false,s=>launched=s) && launched==null,"Missing Telegram handler");
                Check(TelegramLauncher.Open(a,()=>true,s=>launched=s) && launched==a.DeepLink,"Launch exact Telegram deep link");
                Check(!TelegramLauncher.Open(a,()=>true,s=>{throw new System.ComponentModel.Win32Exception();}),"Handle launch failure");
                Check(ProxyParser.Parse(Link.Replace("/proxy?","/webproxy?")).Count==0,"Reject WEB");
                Check(ProxyParser.Parse(Link+"&port=80").Count==0,"Reject duplicate parameters");
                Check(ProxyParser.Parse(Link.Replace("443","70000")).Count==0,"Reject port");
                Check(ProxyParser.Parse(Link.Replace("t.me/","evil.test/")).Count==0,"Reject foreign host");
                Check(ProxyParser.Parse(Link+"\n"+Link).Count==1,"Deduplicate");
                var b=ProxyParser.Parse(Link+"&v=2").Single();
                var results=new[] { new ProbeResult(a,20),new ProbeResult(b,90) };
                Check(Selector.Best(results,null)==a,"Choose fastest");
                Check(Selector.Best(results,a.Link)==b,"Retry alternative");
                Check(Selector.Best(new ProbeResult[0],null)==null,"No available proxy");
                Check(Selector.Best(new[] { results[0] },a.Link)==a,"Single surviving proxy");
                var dir=Path.Combine(Path.GetTempPath(),"tgproxy-test-"+Guid.NewGuid()); Directory.CreateDirectory(dir);
                try {
                    var repo=new ProxyRepository(Path.Combine(dir,"cache"),()=>Link);
                    Check(repo.Load(()=>{throw new IOException();}).Single().Link==Link,"Bundled fallback");
                    Check(repo.Load(()=>b.Link).Single().Link==b.Link,"Fresh list");
                    Check(repo.Load(()=>{throw new IOException();}).Single().Link==b.Link,"Cache fallback");
                    Check(repo.Load(()=>"bad").Single().Link==b.Link,"Invalid download keeps cache");
                } finally { Directory.Delete(dir,true); }
                var nonce=Enumerable.Range(0,16).Select(x=>(byte)x).ToArray();
                var response=new byte[84]; BitConverter.GetBytes(64).CopyTo(response,16); BitConverter.GetBytes(0x05162463).CopyTo(response,20); nonce.CopyTo(response,24);
                Check(MtProbe.ValidReply(response,nonce),"Matching resPQ");
                Check(!MtProbe.ValidReply(response,new byte[16]),"Reject wrong nonce");
                Check(!MtProbe.ValidReply(new byte[12],nonce),"Reject short response");
                var listener=new TcpListener(IPAddress.Loopback,0); listener.Start();
                var server=Task.Run(()=> { using(var c=listener.AcceptTcpClient()) { var data=System.Text.Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n\r\n"); c.GetStream().Write(data,0,data.Length); } listener.Stop(); });
                var fake=ProxyParser.Parse(Link.Replace("example.com&port=443","127.0.0.1&port="+((IPEndPoint)listener.LocalEndpoint).Port)).Single();
                Check(!MtProbe.Check(fake,CancellationToken.None).HasValue,"Reject TCP-only HTTP listener"); server.Wait(3000);
                if(args.Contains("--live")) {
                    var cache=Path.Combine(Path.GetTempPath(),"tg-live-"+Guid.NewGuid());
                    try {
                        var proxies=new ProxyRepository(cache,()=>{throw new Exception("Download failed");}).Load();
                        Check(proxies.Count>0,"Live GitHub download");
                        var found=Selector.CheckAsync(proxies,CancellationToken.None).GetAwaiter().GetResult();
                        Console.WriteLine("LIVE parsed="+proxies.Count+" verified="+found.Count);
                        foreach(var r in found) Console.WriteLine("LIVE "+r.Proxy.Host+" "+r.Millis+"ms");
                        Console.WriteLine("SELECTED "+(Selector.Best(found,null)==null?"NONE":Selector.Best(found,null).Host));
                    } finally { if(File.Exists(cache)) File.Delete(cache); }
                }
                Console.WriteLine("OK "+count+" tests"); return 0;
            } catch(Exception e) { Console.Error.WriteLine(e); return 1; }
        }
    }
}
