using System;
using System.ComponentModel;
using System.Diagnostics;
using Microsoft.Win32;

namespace TgProxy {
    static class TelegramLauncher {
        public static bool HasHandler() {
            try {
                using(var command=Registry.ClassesRoot.OpenSubKey(@"tg\shell\open\command")) {
                    if(command!=null && !string.IsNullOrWhiteSpace(command.GetValue(null) as string)) return true;
                }
                // Store-installed clients may use a per-user protocol association.
                using(var choice=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\tg\UserChoice")) {
                    var id=choice==null?null:choice.GetValue("ProgId") as string;
                    if(!string.IsNullOrEmpty(id)) using(var registered=Registry.ClassesRoot.OpenSubKey(id)) return registered!=null;
                }
            } catch(System.Security.SecurityException) { } catch(UnauthorizedAccessException) { }
            return false;
        }
        public static bool Open(Proxy p,Func<bool> hasHandler=null,Action<string> start=null) {
            if(!(hasHandler ?? HasHandler)()) return false;
            try {
                if(start!=null) start(p.DeepLink);
                else Process.Start(new ProcessStartInfo(p.DeepLink) { UseShellExecute=true });
                return true;
            } catch(Win32Exception) { return false; } catch(InvalidOperationException) { return false; }
        }
    }
}
