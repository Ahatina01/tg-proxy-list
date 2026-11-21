using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace TgProxy {
    sealed class Proxy {
        public string Link, Host, Domain;
        public int Port;
        public byte[] Key;
        public bool Padded;
        public string DeepLink { get { return "tg://proxy?" + Link.Substring(Link.IndexOf('?')+1); } }
    }
    static class ProxyParser {
        public static List<Proxy> Parse(string text) {
            var result=new List<Proxy>(); var seen=new HashSet<string>();
            foreach(var line in text.Split(new[] {'\r','\n'},StringSplitOptions.RemoveEmptyEntries)) {
                string link=line.Trim(); if(!seen.Add(link)) continue;
                try {
                    var u=new Uri(link);
                    if(u.Scheme!="https" || u.Host!="t.me" || u.AbsolutePath!="/proxy" || u.Fragment!="" || u.UserInfo!="" || !u.IsDefaultPort) continue;
                    var query=link.Substring(link.IndexOf('?')+1);
                    var p=new Dictionary<string,string>();
                    foreach(var part in query.Split('&')) {
                        var i=part.IndexOf('='); if(i<1) throw new FormatException();
                        p.Add(Uri.UnescapeDataString(part.Substring(0,i).Replace("+"," ")),Uri.UnescapeDataString(part.Substring(i+1).Replace("+"," ")));
                    }
                    var host=p["server"]; int port=int.Parse(p["port"]);
                    if(host.Length<1 || host.Length>253 || !Regex.IsMatch(host,@"^[a-zA-Z0-9.:-]+$") || port<1 || port>65535) continue;
                    var secret=p["secret"]; byte[] key;
                    if(secret.Length%2==0 && Regex.IsMatch(secret,"^[a-fA-F0-9]+$")) key=Wire.Hex(secret);
                    else { var b64=secret.Replace('-','+').Replace('_','/'); key=Convert.FromBase64String(b64.PadRight((b64.Length+3)/4*4,'=')); }
                    bool tls=key.Length>17 && key[0]==0xee;
                    if(!(key.Length==16 || (key.Length==17 && key[0]==0xdd) || tls)) continue;
                    string domain=tls?Encoding.ASCII.GetString(key,17,key.Length-17):null;
                    if(domain!=null && (domain.Length>253 || !Regex.IsMatch(domain,"^[a-zA-Z0-9.-]+$"))) continue;
                    result.Add(new Proxy { Link=link,Host=host,Port=port,Key=key.Length==16?key:key.Skip(1).Take(16).ToArray(),Domain=domain,Padded=key.Length!=16 });
                    if(result.Count==256) break;
                } catch(Exception e) { if(!(e is FormatException || e is ArgumentException || e is KeyNotFoundException || e is OverflowException)) throw; }
            }
            return result;
        }
    }
    sealed class ProbeResult {
        public Proxy Proxy; public long Millis;
        public ProbeResult(Proxy p,long ms) { Proxy=p; Millis=ms; }
    }
    static class Selector {
        public static Proxy Best(IEnumerable<ProbeResult> results,string previous) {
            var list=results.OrderBy(r=>r.Millis).ToList();
            var selected=list.FirstOrDefault(r=>r.Proxy.Link!=previous) ?? list.FirstOrDefault();
            return selected==null?null:selected.Proxy;
        }
        public static async Task<List<ProbeResult>> CheckAsync(List<Proxy> proxies,CancellationToken token) {
            using(var timeout=CancellationTokenSource.CreateLinkedTokenSource(token))
            using(var gate=new SemaphoreSlim(8)) {
                timeout.CancelAfter(12000);
                var results=new List<ProbeResult>();
                var tasks=proxies.OrderBy(p=>Guid.NewGuid()).Select(async p=> {
                    bool entered=false;
                    try {
                        await gate.WaitAsync(timeout.Token).ConfigureAwait(false); entered=true;
                        var ms=await Task.Run(()=>MtProbe.Check(p,timeout.Token)).ConfigureAwait(false);
                        if(ms.HasValue) lock(results) results.Add(new ProbeResult(p,ms.Value));
                    } catch(OperationCanceledException) { }
                    finally { if(entered) gate.Release(); }
                }).ToArray();
                await Task.WhenAll(tasks).ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                return results;
            }
        }
    }
    sealed class ProxyRepository {
        public const string Source="https://raw.githubusercontent.com/Ahatina01/tg-proxy-list/main/proxies.txt";
        readonly string cache; readonly Func<string> bundled;
        public ProxyRepository(string path,Func<string> fallback) { cache=path; bundled=fallback; }
        public List<Proxy> Load(Func<string> fetch=null) {
            try {
                string text=(fetch ?? Download)(); var parsed=ProxyParser.Parse(text);
                if(parsed.Count==0) throw new IOException("No supported proxies");
                try {
                    Directory.CreateDirectory(Path.GetDirectoryName(cache));
                    var temp=cache+"."+Guid.NewGuid()+".tmp";
                    try { File.WriteAllText(temp,text,Encoding.UTF8); if(File.Exists(cache)) File.Replace(temp,cache,null); else File.Move(temp,cache); }
                    finally { if(File.Exists(temp)) File.Delete(temp); }
                } catch(IOException) { } catch(UnauthorizedAccessException) { }
                return parsed;
            } catch(Exception e) {
                if(!(e is IOException || e is WebException || e is ArgumentException || e is InvalidOperationException || e is System.Security.SecurityException)) throw;
                try { var saved=ProxyParser.Parse(File.ReadAllText(cache)); if(saved.Count>0) return saved; } catch(IOException) {} catch(UnauthorizedAccessException) {}
                return ProxyParser.Parse(bundled());
            }
        }
        static string Download() {
            ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
            var request=(HttpWebRequest)WebRequest.Create(Source);
            request.Timeout=4000; request.ReadWriteTimeout=3000;
            request.UserAgent="TG-Proxy-Windows/1.0";
            request.CachePolicy=new System.Net.Cache.RequestCachePolicy(System.Net.Cache.RequestCacheLevel.NoCacheNoStore);
            request.Headers[HttpRequestHeader.CacheControl]="no-cache, no-store";
            using(var deadline=new Timer(_=>request.Abort(),null,6500,Timeout.Infinite))
            using(var response=(HttpWebResponse)request.GetResponse())
            using(var input=response.GetResponseStream())
            using(var output=new MemoryStream()) {
                if(response.StatusCode!=HttpStatusCode.OK) throw new IOException();
                var b=new byte[8192]; int n;
                while((n=input.Read(b,0,b.Length))>0) { if(output.Length+n>262144) throw new IOException(); output.Write(b,0,n); }
                return Encoding.UTF8.GetString(output.ToArray());
            }
        }
    }
}
