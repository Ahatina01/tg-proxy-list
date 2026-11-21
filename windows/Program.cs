using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

[assembly: AssemblyTitle("TG Proxy")]
[assembly: AssemblyProduct("TG Proxy")]
[assembly: AssemblyDescription("Telegram proxy selector for Windows")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace TgProxy {
    static class Program {
        [STAThread] static void Main() {
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainWindow());
        }
    }
    sealed class MainWindow : Form {
        readonly ConnectButton button=new ConnectButton();
        readonly Label status=new Label();
        readonly CancellationTokenSource lifetime=new CancellationTokenSource();
        readonly string data=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"TG Proxy");
        string previous; bool busy;
        [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd,int attribute,ref int value,int size);
        public MainWindow() {
            Text="TG Proxy"; ClientSize=new Size(440,520); MinimumSize=new Size(390,490); MaximizeBox=false;
            StartPosition=FormStartPosition.CenterScreen; AutoScaleMode=AutoScaleMode.Dpi;
            Font=new Font("Segoe UI",10); BackColor=Color.FromArgb(10,17,29); ForeColor=Color.White;
            DoubleBuffered=true;
            using(var resource=Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico")) if(resource!=null) Icon=new Icon(resource);
            button.Text="Подключить"; button.AccessibleName="Подключить"; button.Cursor=Cursors.Hand;
            button.Font=new Font("Segoe UI Semibold",14); button.Click+=async (s,e)=>await Connect();
            status.Text="Прокси для вашего Telegram"; status.TextAlign=ContentAlignment.TopCenter;
            status.ForeColor=Color.FromArgb(155,172,195); status.BackColor=Color.Transparent; status.AutoSize=false;
            status.AccessibleName="Статус подключения"; Controls.Add(button); Controls.Add(status);
            Resize+=(s,e)=>Arrange(); Arrange();
            try { previous=File.ReadAllText(Path.Combine(data,"previous.txt")); } catch(IOException) {} catch(UnauthorizedAccessException) {}
            FormClosed+=(s,e)=>lifetime.Cancel();
        }
        protected override void OnHandleCreated(EventArgs e) {
            base.OnHandleCreated(e);
            try { int dark=1; DwmSetWindowAttribute(Handle,20,ref dark,4); } catch(DllNotFoundException) {} catch(EntryPointNotFoundException) {}
        }
        void Arrange() {
            float scale=DeviceDpi/96f;
            int width=Math.Min(ClientSize.Width-(int)(80*scale),(int)(344*scale));
            int y=(int)(ClientSize.Height*0.59);
            button.SetBounds((ClientSize.Width-width)/2,y,width,(int)(64*scale));
            status.SetBounds((int)(24*scale),button.Bottom+(int)(23*scale),ClientSize.Width-(int)(48*scale),(int)(74*scale));
            Invalidate();
        }
        protected override void OnPaintBackground(PaintEventArgs e) {
            using(var brush=new LinearGradientBrush(ClientRectangle,Color.FromArgb(20,35,57),Color.FromArgb(8,13,23),65)) e.Graphics.FillRectangle(brush,ClientRectangle);
        }
        protected override void OnPaint(PaintEventArgs e) {
            base.OnPaint(e); var g=e.Graphics; g.SmoothingMode=SmoothingMode.AntiAlias;
            float s=DeviceDpi/96f, cx=ClientSize.Width/2f, cy=ClientSize.Height*0.265f;
            using(var halo=new SolidBrush(Color.FromArgb(14,82,169))) g.FillEllipse(halo,cx-53*s,cy-53*s,106*s,106*s);
            using(var blue=new LinearGradientBrush(new RectangleF(cx-42*s,cy-42*s,84*s,84*s),Color.FromArgb(50,161,255),Color.FromArgb(20,115,235),70)) g.FillEllipse(blue,cx-42*s,cy-42*s,84*s,84*s);
            var points=new[] {new PointF(-25,-3),new PointF(25,-23),new PointF(15,24),new PointF(-2,10),new PointF(-12,20),new PointF(-10,4),new PointF(14,-13),new PointF(-17,1)};
            for(int i=0;i<points.Length;i++) points[i]=new PointF(cx+points[i].X*s,cy+points[i].Y*s);
            g.FillPolygon(Brushes.White,points);
            using(var title=new Font("Segoe UI Semibold",26)) {
                var rect=new Rectangle(0,(int)(cy+65*s),ClientSize.Width,(int)(52*s));
                TextRenderer.DrawText(g,"TG Proxy",title,rect,Color.White,TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter);
            }
        }
        static string Bundled() {
            using(var s=Assembly.GetExecutingAssembly().GetManifestResourceStream("proxies.txt"))
            using(var reader=new StreamReader(s)) return reader.ReadToEnd();
        }
        async Task Connect() {
            if(busy) return;
            busy=true; button.Enabled=false; status.Text="Поиск прокси…";
            try {
                var proxies=await Task.Run(()=>new ProxyRepository(Path.Combine(data,"proxies.txt"),Bundled).Load());
                lifetime.Token.ThrowIfCancellationRequested();
                var results=await Selector.CheckAsync(proxies,lifetime.Token);
                if(IsDisposed) return;
                var selected=Selector.Best(results,previous);
                if(selected==null) { status.Text="Нет доступных прокси.\nПопробуйте ещё раз"; return; }
                status.Text="Открываем Telegram…"; status.Refresh();
                bool opened=await Task.Run(()=>TelegramLauncher.Open(selected));
                if(IsDisposed) return;
                if(opened) {
                    previous=selected.Link;
                    try { Directory.CreateDirectory(data); File.WriteAllText(Path.Combine(data,"previous.txt"),previous); } catch(IOException) {} catch(UnauthorizedAccessException) {}
                    status.Text="Подтвердите подключение\nв Telegram";
                } else status.Text="Установите Telegram Desktop\nи откройте его один раз";
            } catch(OperationCanceledException) { }
            catch(Exception) { if(!IsDisposed) status.Text="Ошибка подключения"; }
            finally { busy=false; if(!IsDisposed) button.Enabled=true; }
        }
    }
    sealed class ConnectButton : Button {
        public ConnectButton() { SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.SupportsTransparentBackColor,true); FlatStyle=FlatStyle.Flat; FlatAppearance.BorderSize=0; BackColor=Color.Transparent; }
        protected override void OnResize(EventArgs e) {
            base.OnResize(e);
            if(Width<2 || Height<2) return;
            int d=Math.Min(44*DeviceDpi/96,Math.Min(Width,Height));
            using(var path=new GraphicsPath()) {
                path.AddArc(0,0,d,d,180,90); path.AddArc(Width-d,0,d,d,270,90);
                path.AddArc(Width-d,Height-d,d,d,0,90); path.AddArc(0,Height-d,d,d,90,90); path.CloseFigure();
                var old=Region; Region=new Region(path); if(old!=null) old.Dispose();
            }
        }
        protected override void OnPaint(PaintEventArgs e) {
            var g=e.Graphics; g.SmoothingMode=SmoothingMode.AntiAlias;
            int r=22*DeviceDpi/96; var bounds=new Rectangle(1,1,Width-3,Height-3);
            using(var path=new GraphicsPath()) {
                path.AddArc(bounds.Left,bounds.Top,r*2,r*2,180,90); path.AddArc(bounds.Right-r*2,bounds.Top,r*2,r*2,270,90);
                path.AddArc(bounds.Right-r*2,bounds.Bottom-r*2,r*2,r*2,0,90); path.AddArc(bounds.Left,bounds.Bottom-r*2,r*2,r*2,90,90); path.CloseFigure();
                using(var brush=new LinearGradientBrush(bounds,Enabled?Color.FromArgb(22,121,239):Color.FromArgb(30,65,105),Enabled?Color.FromArgb(50,156,255):Color.FromArgb(38,82,124),0f)) g.FillPath(brush,path);
                if(Focused) using(var pen=new Pen(Color.FromArgb(170,220,255),2)) g.DrawPath(pen,path);
            }
            TextRenderer.DrawText(g,Text,Font,bounds,Color.White,TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter);
        }
    }
}
