<#
    =====================================================================
      Gelişmiş Mod Analyzer  v3.0.0
      Yapımcı : XTALE
      Discord : https://discord.gg/njvChGfE9P
      (Habibi Mod Analyzer - HadronCollision temel alınmıştır)
    =====================================================================

    Tek satırla çalıştırma (GitHub'a yükledikten sonra):
      powershell -ExecutionPolicy Bypass -Command "iex ((irm 'RAW_LINK').TrimStart([char]0xFEFF))"
#>

# =====================================================================
#  AYARLAR  (GitHub'a yükledikten sonra linkleri doldurun)
# =====================================================================
$ScriptVersion = '3.0.0'
$Config = @{
    # CurseForge API anahtarı (https://console.curseforge.com adresinden ücretsiz alınır). Boşsa CurseForge kontrolü atlanır.
    CurseForgeApiKey = ''
    # Uzak imza listesi (signatures.json dosyasının RAW linki). Boşsa sadece yerleşik liste kullanılır.
    SignaturesUrl    = ''
    # Sürüm kontrolü (version.txt dosyasının RAW linki). Boşsa sürüm kontrolü atlanır.
    VersionUrl       = ''
    # Yeni sürüm çıkınca gösterilecek indirme linki
    UpdateUrl        = 'https://discord.gg/njvChGfE9P'
    # Bellek taramasında okunacak en fazla veri (GB)
    MemoryScanMaxGB  = 3
}

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# =====================================================================
#  C# yardımcıları (CurseForge murmur2, bellek tarama, aygıt yolu)
# =====================================================================
if (-not ('XtaleMA3' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

public static class XtaleMA3
{
    public static uint Murmur2(byte[] data)
    {
        List<byte> n = new List<byte>(data.Length);
        foreach (byte b in data) { if (b != 9 && b != 10 && b != 13 && b != 32) n.Add(b); }
        byte[] d = n.ToArray();
        const uint m = 0x5bd1e995;
        int len = d.Length;
        uint h = 1u ^ (uint)len;
        int i = 0;
        while (len >= 4)
        {
            uint k = (uint)(d[i] | (d[i + 1] << 8) | (d[i + 2] << 16) | (d[i + 3] << 24));
            k *= m; k ^= k >> 24; k *= m;
            h *= m; h ^= k;
            i += 4; len -= 4;
        }
        switch (len)
        {
            case 3: h ^= (uint)d[i + 2] << 16; h ^= (uint)d[i + 1] << 8; h ^= d[i]; h *= m; break;
            case 2: h ^= (uint)d[i + 1] << 8; h ^= d[i]; h *= m; break;
            case 1: h ^= d[i]; h *= m; break;
        }
        h ^= h >> 13; h *= m; h ^= h >> 15;
        return h;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MBI
    {
        public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
        public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI info, IntPtr len);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern uint QueryDosDevice(string dev, StringBuilder target, int max);

    public static string DosDevice(string drive)
    {
        StringBuilder sb = new StringBuilder(1024);
        if (QueryDosDevice(drive, sb, 1024) != 0) return sb.ToString();
        return null;
    }

    public static long LastScanned = 0;

    public static Dictionary<string, int> ScanProcess(int pid, string pattern, long maxBytes)
    {
        Dictionary<string, int> result = new Dictionary<string, int>();
        IntPtr h = OpenProcess(0x0400 | 0x0010, false, pid);
        if (h == IntPtr.Zero) return null;
        Regex rx = new Regex(pattern, RegexOptions.Compiled);
        Encoding latin = Encoding.GetEncoding(28591);
        long addr = 0, total = 0;
        int chunkMax = 16 * 1024 * 1024;
        byte[] buf = new byte[chunkMax];
        MBI mbi;
        IntPtr mbiSize = (IntPtr)Marshal.SizeOf(typeof(MBI));
        try
        {
            while (total < maxBytes && VirtualQueryEx(h, new IntPtr(addr), out mbi, mbiSize) != IntPtr.Zero)
            {
                long size = mbi.RegionSize.ToInt64();
                if (size <= 0) break;
                bool readable = mbi.State == 0x1000 && (mbi.Protect & 0x100) == 0 && (mbi.Protect & 0x01) == 0 && (mbi.Protect & 0xEE) != 0;
                if (readable && (mbi.Type == 0x20000 || mbi.Type == 0x40000))
                {
                    long off = 0;
                    while (off < size && total < maxBytes)
                    {
                        int chunk = (int)Math.Min((long)chunkMax, size - off);
                        IntPtr read;
                        if (ReadProcessMemory(h, new IntPtr(addr + off), buf, (IntPtr)chunk, out read) && read.ToInt64() > 0)
                        {
                            int n = (int)read.ToInt64();
                            total += n;
                            foreach (Match mt in rx.Matches(latin.GetString(buf, 0, n))) Add(result, mt.Value);
                            foreach (Match mt in rx.Matches(Encoding.Unicode.GetString(buf, 0, n - (n % 2)))) Add(result, mt.Value);
                        }
                        off += chunk;
                    }
                }
                addr += size;
            }
        }
        finally { CloseHandle(h); LastScanned = total; }
        return result;
    }

    static void Add(Dictionary<string, int> d, string k)
    {
        int c; if (d.TryGetValue(k, out c)) d[k] = c + 1; else d[k] = 1;
    }
}
'@
}

# =====================================================================
#  Çıktı, dil ve rapor yardımcıları
# =====================================================================
$Script:Lang     = 'tr'
$Script:Report   = New-Object System.Collections.Generic.List[string]
$Script:Html     = New-Object System.Text.StringBuilder
$Script:LineBuf  = ''
$Script:SysFlags = 0
$Script:Recording = $true

function L { param([string]$tr, [string]$en) if ($Script:Lang -eq 'en') { return $en } return $tr }

$CssColors = @{
    Black='#000000'; DarkBlue='#3b5bdb'; DarkGreen='#2f9e44'; DarkCyan='#1c9fb8'; DarkRed='#c92a2a'
    DarkMagenta='#ae3ec9'; DarkYellow='#e8a33d'; Gray='#c9ccd1'; DarkGray='#7d8590'; Blue='#4dabf7'
    Green='#51cf66'; Cyan='#3bc9db'; Red='#ff6b6b'; Magenta='#f783ac'; Yellow='#ffd43b'; White='#ffffff'
}

function W {
    param([string]$Text = '', [string]$Color = 'Gray', [switch]$NoNewline)
    if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline }
    else            { Write-Host $Text -ForegroundColor $Color }
    if (-not $Script:Recording) { return }
    $Script:LineBuf += $Text
    [void]$Script:Html.Append('<span style="color:' + $CssColors[$Color] + '">' + [System.Net.WebUtility]::HtmlEncode($Text) + '</span>')
    if (-not $NoNewline) {
        $Script:Report.Add($Script:LineBuf); $Script:LineBuf = ''
        [void]$Script:Html.Append("`n")
    }
}

function Section {
    param([string]$Title)
    W
    W ('=' * 72) 'DarkGray'
    W "  $Title" 'Cyan'
    W ('=' * 72) 'DarkGray'
}

function Warn { param([string]$Text) $Script:SysFlags++; W "  [!] $Text" 'Red' }
function Note { param([string]$Text) W "  [i] $Text" 'DarkGray' }

function Format-Size { param([long]$Bytes) if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) } return ('{0:N1} KB' -f ($Bytes / 1KB)) }
function Format-Span { param([TimeSpan]$S) return ((L '{0}g {1}s {2}dk {3}sn' '{0}d {1}h {2}m {3}s') -f $S.Days, $S.Hours, $S.Minutes, $S.Seconds) }
function Format-Date { param($D) if ($D) { return ([datetime]$D).ToString('dd.MM.yyyy HH:mm:ss') } return '-' }

function Ask-YesNo {
    param([string]$Question, [bool]$Default = $true)
    $hint = if ($Default) { L '(E/h)' '(Y/n)' } else { L '(e/H)' '(y/N)' }
    $a = Read-Host "  $Question $hint"
    if (-not $a) { return $Default }
    return ($a -match '^(e|y|evet|yes)$')
}

# =====================================================================
#  Başlangıç: dil seçimi, başlık, yönetici ve sürüm kontrolü
# =====================================================================
Clear-Host
Write-Host ''
Write-Host '  Dil / Language:  [1] Türkçe   [2] English' -ForegroundColor White
$langChoice = Read-Host '  >'
if ($langChoice -eq '2') { $Script:Lang = 'en' }
Clear-Host

W '  __  __           _     _                _                     ' 'Red'
W ' |  \/  | ___   __| |   / \   _ __   __ _| |_   _ _______ _ __ ' 'Red'
W ' | |\/| |/ _ \ / _` |  / _ \ | ''_ \ / _` | | | | |_  / _ \ ''__|' 'Red'
W ' | |  | | (_) | (_| | / ___ \| | | | (_| | | |_| |/ /  __/ |   ' 'Red'
W ' |_|  |_|\___/ \__,_|/_/   \_\_| |_|\__,_|_|\__, /___\___|_|   ' 'Red'
W '                                            |___/              ' 'Red'
W ("  " + (L 'Gelişmiş Mod Analyzer' 'Advanced Mod Analyzer') + " v$ScriptVersion") 'White' -NoNewline
W '  |  Made by ' 'DarkGray' -NoNewline
W 'XTALE' 'Red'
W '  Discord: ' 'DarkGray' -NoNewline
W 'discord.gg/njvChGfE9P' 'Cyan'
W ("  {0}: {1}  |  {2}: {3}  |  PC: {4}" -f (L 'Tarih' 'Date'), (Get-Date -Format 'dd.MM.yyyy HH:mm:ss'), (L 'Kullanıcı' 'User'), $env:USERNAME, $env:COMPUTERNAME) 'DarkGray'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    W ('  [!] ' + (L 'Yönetici olarak çalıştırılmıyor. Prefetch, BAM, USN ve bazı süreç kontrolleri eksik kalacak.' 'Not running as administrator. Prefetch, BAM, USN and some process checks will be limited.')) 'Yellow'
}

if ($Config.VersionUrl) {
    try {
        $remoteVer = (Invoke-RestMethod -Uri $Config.VersionUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop).ToString().Trim().TrimStart([char]0xFEFF)
        if ([version]$remoteVer -gt [version]$ScriptVersion) {
            W ('  [!] ' + (L "Yeni sürüm mevcut: v$remoteVer (sizdeki: v$ScriptVersion)  ->  $($Config.UpdateUrl)" "New version available: v$remoteVer (yours: v$ScriptVersion)  ->  $($Config.UpdateUrl)")) 'Yellow'
        } else {
            W ('  ' + (L 'Script güncel.' 'Script is up to date.')) 'DarkGray'
        }
    } catch { W ('  ' + (L 'Sürüm kontrolü yapılamadı.' 'Version check failed.')) 'DarkGray' }
}

$bootTime = $null
try { $bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime } catch {}

# =====================================================================
#  İmzalar (yerleşik + yerel signatures.json + uzak liste)
# =====================================================================
$StrongStrings = New-Object System.Collections.Generic.List[string]
$WeakStrings   = New-Object System.Collections.Generic.List[string]
$ClientSignatures = @{}
$HashBlacklist    = @{}
$SuspiciousProcNames = New-Object System.Collections.Generic.List[string]

@('AimAssist','AnchorTweaks','AutoAnchor','AutoCrystal','AutoDoubleHand','AutoHitCrystal','AutoPot','AutoTotem',
  'InventoryTotem','LegitTotem','HoverTotem','PingSpoof','SelfDestruct','ShieldBreaker','TriggerBot','AxeSpam',
  'WebMacro','KillAura','AutoClicker','CrystalAura','AnchorAura','BedAura','AutoMace','MaceSwap','ElytraSwap',
  'AutoInventoryTotem','SilentAim','CwCrystal','DoubleAnchor','SafeAnchor','AutoWTap','AutoJumpReset','Backtrack',
  'FakeLag','KeyPearl','AutoXP') | ForEach-Object { $StrongStrings.Add($_) }
@('Velocity','Reach','Hitboxes','FastPlace','JumpReset','AutoArmor','NoSlow','Criticals','WTap','STap','BlockHit',
  'Blink','NoFall','Scaffold','Freecam','Xray','Macro','Clicker','Spoof','Bypass','Cheat') | ForEach-Object { $WeakStrings.Add($_) }
$ClientSignatures = @{
    'meteordevelopment/meteorclient/' = 'Meteor Client'
    'net/wurstclient/'                = 'Wurst Client'
    'net/ccbluex/liquidbounce/'       = 'LiquidBounce'
    'thunder/hack/'                   = 'ThunderHack'
    'dev/thunderhack/'                = 'ThunderHack'
    'me/alpha432/oyvey/'              = 'OyVey'
    'org/rusherhack/'                 = 'RusherHack'
    'dev/boze/'                       = 'Boze'
    'net/aristois/'                   = 'Aristois'
    'com/doomsday/'                   = 'Doomsday'
    'skid/'                           = 'Skid client'
    'dev/argon/'                      = 'Argon'
    'xyz/prestige/'                   = 'Prestige'
}
@('autoclick','autoclicker','opautoclicker','gsautoclicker','speedautoclicker','clicker','macro','jnativehook',
  'injector','extremeinjector','xenos','dllinject','cheatengine','cheat','hack','vape','slinky','doomsday',
  'entropy','whiteout','koid','akrien','novoline','astolfo','liquidbounce','wurst','meteorclient','aristois',
  'riseclient','drip','prestige','argon','killaura','ghostclient','selfdestruct','autohotkey','tinytask',
  'pulover','jitbit','mousemacro','keymacro','radiant','sigma','tenacity','exhibition','thunderhack') | ForEach-Object { $SuspiciousProcNames.Add($_) }

function Merge-Signatures {
    param($Data, [string]$Origin)
    if (-not $Data) { return }
    $added = 0
    foreach ($s in @($Data.strong))  { if ($s -and -not $StrongStrings.Contains($s)) { $StrongStrings.Add($s); $added++ } }
    foreach ($s in @($Data.weak))    { if ($s -and -not $WeakStrings.Contains($s))   { $WeakStrings.Add($s);   $added++ } }
    foreach ($s in @($Data.processes)) { if ($s -and -not $SuspiciousProcNames.Contains($s.ToLower())) { $SuspiciousProcNames.Add($s.ToLower()); $added++ } }
    if ($Data.clients) { foreach ($p in $Data.clients.PSObject.Properties) { $ClientSignatures[$p.Name.ToLower()] = [string]$p.Value; $added++ } }
    if ($Data.hashes)  { foreach ($p in $Data.hashes.PSObject.Properties)  { $HashBlacklist[$p.Name.ToLower()]    = [string]$p.Value; $added++ } }
    W ("  " + (L "İmza listesi yüklendi ($Origin): $added kayıt" "Signature list loaded ($Origin): $added entries")) 'DarkGray'
}

$localSig = $null
if ($PSScriptRoot) { $localSig = Join-Path $PSScriptRoot 'signatures.json' }
if ($localSig -and (Test-Path -LiteralPath $localSig)) {
    try { Merge-Signatures ((Get-Content -LiteralPath $localSig -Raw -Encoding UTF8).TrimStart([char]0xFEFF) | ConvertFrom-Json) (L 'yerel' 'local') } catch {}
}
if ($Config.SignaturesUrl) {
    try {
        $raw = Invoke-WebRequest -Uri $Config.SignaturesUrl -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        $txt = [System.Text.Encoding]::UTF8.GetString($raw.RawContentStream.ToArray()).TrimStart([char]0xFEFF)
        Merge-Signatures ($txt | ConvertFrom-Json) (L 'uzak' 'remote')
    } catch { W ("  " + (L 'Uzak imza listesi alınamadı, yerleşik liste kullanılıyor.' 'Remote signature list unavailable, using built-in list.')) 'DarkYellow' }
}

$StrongRx = [regex]::new('(' + (($StrongStrings | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')')
$WeakRx   = [regex]::new('(' + (($WeakStrings   | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')')
$ProcRx   = [regex]::new('(' + (($SuspiciousProcNames | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')', 'IgnoreCase')
$Latin1   = [System.Text.Encoding]::GetEncoding(28591)
$SuspiciousHosts = 'discordapp\.(com|net)|discord\.com|mediafire|mega\.(nz|io)|gofile|anonfiles|dropbox|drive\.google|pixeldrain|transfer\.sh|catbox|sendspace|workupload|qu\.ax|bit\.ly|tinyurl'

# =====================================================================
#  Minecraft süreç analizi
# =====================================================================
Section (L 'MINECRAFT SÜREÇ ANALİZİ' 'MINECRAFT PROCESS ANALYSIS')

if ($bootTime) { W ("  " + (L 'Sistem açılışı' 'System boot') + ": $(Format-Date $bootTime)  ($(Format-Span ((Get-Date) - $bootTime)))") 'Gray' }

$mcStart   = $null
$mcPids    = New-Object System.Collections.Generic.List[int]
$gameDirs  = New-Object System.Collections.Generic.List[string]
$javaProcs = @(Get-CimInstance Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'")

if ($javaProcs.Count -eq 0) {
    W ("  " + (L 'Çalışan java/javaw süreci bulunamadı.' 'No running java/javaw process found.')) 'DarkYellow'
} else {
    foreach ($p in $javaProcs) {
        $cmd   = [string]$p.CommandLine
        $start = $p.CreationDate
        $isMc  = $cmd -match 'net\.minecraft|fabric|forge|quilt|neoforge|--gameDir|lunar|badlion|feather|minecraft'
        if (-not $cmd) { $isMc = $true }

        W ("  > {0} (PID {1})" -f $p.Name, $p.ProcessId) 'White' -NoNewline
        if ($isMc) { W '  [Minecraft]' 'Green' } else { W ('  [' + (L 'Diğer Java' 'Other Java') + ']') 'DarkGray' }
        if ($isMc) { $mcPids.Add([int]$p.ProcessId) }

        if ($start) {
            W ("    {0}: {1}   {2}: {3}" -f (L 'Başlangıç' 'Started'), (Format-Date $start), (L 'Çalışma süresi' 'Uptime'), (Format-Span ((Get-Date) - $start))) 'Gray'
            if ($isMc -and (-not $mcStart -or $start -lt $mcStart)) { $mcStart = $start }
        }
        if ($cmd) {
            if ($cmd -match '--gameDir\s+(?:"([^"]+)"|(\S+))') {
                $gd = if ($matches[1]) { $matches[1] } else { $matches[2] }
                if (-not $gameDirs.Contains($gd)) { $gameDirs.Add($gd) }
                W "    GameDir: $gd" 'Gray'
            }
            foreach ($a in [regex]::Matches($cmd, '(-javaagent:\S+|-agentpath:\S+|-agentlib:\S+|-Xbootclasspath\S*)')) {
                Warn ((L 'Şüpheli JVM argümanı' 'Suspicious JVM argument') + ": $($a.Value)")
            }
        } elseif (-not $isAdmin) {
            Note (L 'Komut satırı okunamadı (yönetici izni gerekli).' 'Command line unavailable (administrator required).')
        }
    }
}

Section (L 'ÇALIŞAN ŞÜPHELİ SÜREÇLER' 'RUNNING SUSPICIOUS PROCESSES')
$procFound = 0
foreach ($pr in @(Get-CimInstance Win32_Process)) {
    $nm = [System.IO.Path]::GetFileNameWithoutExtension([string]$pr.Name)
    if ($nm -and $ProcRx.IsMatch($nm)) {
        $procFound++
        Warn ("{0} (PID {1})  {2}" -f $pr.Name, $pr.ProcessId, $pr.ExecutablePath)
    }
}
if ($procFound -eq 0) { Note (L 'Şüpheli isimli süreç yok.' 'No suspiciously named processes.') }

# =====================================================================
#  Mods klasörü seçimi
# =====================================================================
Section (L 'MODS KLASÖRÜ' 'MODS FOLDER')

$mcRoot = Join-Path $env:APPDATA '.minecraft'
foreach ($gd in $gameDirs) { if (Test-Path -LiteralPath $gd -PathType Container) { $mcRoot = $gd; break } }
$defaultMods = Join-Path $mcRoot 'mods'

while ($true) {
    Write-Host ("  " + (L 'Mods klasörü yolu' 'Path to mods folder') + ' ') -NoNewline
    Write-Host ("(" + (L 'boş bırakılırsa' 'leave empty for') + ": $defaultMods)") -ForegroundColor DarkGray
    $mods = Read-Host ('  ' + (L 'YOL' 'PATH'))
    if (-not $mods) { $mods = $defaultMods }
    $mods = $mods.Trim('"', ' ')
    if (Test-Path -LiteralPath $mods -PathType Container) { break }
    W ("  " + (L 'Geçersiz yol' 'Invalid path') + ": $mods") 'Red'
}
$mods = (Get-Item -LiteralPath $mods).FullName
W ("  " + (L 'Taranan klasör' 'Scanning folder') + ": $mods") 'White'

$doUsn = $false; $doMem = $false
if ($isAdmin) { $doUsn = Ask-YesNo (L 'USN Journal taraması yapılsın mı? (silinen dosyalar, 1-2 dk sürebilir)' 'Scan USN Journal? (deleted files, may take 1-2 min)') $true }
if ($mcPids.Count -gt 0) { $doMem = Ask-YesNo (L 'Minecraft belleği taransın mı? (birkaç dakika sürebilir)' 'Scan Minecraft memory? (may take a few minutes)') $true }

# =====================================================================
#  Mod yardımcı fonksiyonları
# =====================================================================
$ApiHeaders = @{ 'User-Agent' = "XTALE-ModAnalyzer/$ScriptVersion (discord.gg/njvChGfE9P)" }

function Get-ZoneInfo {
    param([string]$Path)
    $ads = Get-Content -LiteralPath $Path -Raw -Stream Zone.Identifier -ErrorAction SilentlyContinue
    if (-not $ads) { return $null }
    $info = [ordered]@{ HostUrl = $null; ReferrerUrl = $null }
    if ($ads -match 'HostUrl=(.+)')     { $info.HostUrl     = $matches[1].Trim() }
    if ($ads -match 'ReferrerUrl=(.+)') { $info.ReferrerUrl = $matches[1].Trim() }
    return [pscustomobject]$info
}

function Read-EntryBytes {
    param($Entry)
    $s = $Entry.Open(); $ms = New-Object System.IO.MemoryStream
    try { $s.CopyTo($ms); return ,$ms.ToArray() } finally { $s.Dispose(); $ms.Dispose() }
}

function Get-Sha1Hex { param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try { return (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
}

function Get-ModrinthBatch {
    param([string[]]$Hashes)
    $result = @{}
    if (-not $Hashes -or $Hashes.Count -eq 0) { return $result }
    try {
        $body = '{"algorithm":"sha1","hashes":[' + (($Hashes | ForEach-Object { '"' + $_ + '"' }) -join ',') + ']}'
        $versions = Invoke-RestMethod -Uri 'https://api.modrinth.com/v2/version_files' -Method Post -Body $body `
                    -ContentType 'application/json' -Headers $ApiHeaders -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        $map = @{}
        foreach ($prop in $versions.PSObject.Properties) { $map[$prop.Name] = $prop.Value }
        $ids = @($map.Values | ForEach-Object { $_.project_id } | Where-Object { $_ } | Select-Object -Unique)
        $projects = @{}
        for ($i = 0; $i -lt $ids.Count; $i += 100) {
            $chunk = $ids[$i..([Math]::Min($i + 99, $ids.Count - 1))]
            $json  = '[' + (($chunk | ForEach-Object { '"' + $_ + '"' }) -join ',') + ']'
            $resp  = Invoke-RestMethod -Uri ('https://api.modrinth.com/v2/projects?ids=' + [uri]::EscapeDataString($json)) -Headers $ApiHeaders -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
            foreach ($pr in @($resp | ForEach-Object { $_ })) { $projects[$pr.id] = $pr }
        }
        foreach ($h in $map.Keys) {
            $v = $map[$h]; $pr = $projects[$v.project_id]
            $result[$h.ToLower()] = [pscustomobject]@{
                Name    = if ($pr) { $pr.title } else { $v.name }
                Version = $v.version_number
            }
        }
    } catch { W ("  [!] " + (L 'Modrinth sorgusu başarısız' 'Modrinth query failed') + ": $($_.Exception.Message)") 'DarkYellow' }
    return $result
}

function Get-CurseForgeBatch {
    param([hashtable]$Fingerprints)   # fingerprint(uint) -> sha1
    $result = @{}
    if (-not $Config.CurseForgeApiKey -or $Fingerprints.Count -eq 0) { return $result }
    $h = @{ 'x-api-key' = $Config.CurseForgeApiKey; 'Accept' = 'application/json' }
    try {
        $body = '{"fingerprints":[' + (($Fingerprints.Keys | ForEach-Object { [string]$_ }) -join ',') + ']}'
        $resp = Invoke-RestMethod -Uri 'https://api.curseforge.com/v1/fingerprints/432' -Method Post -Body $body -ContentType 'application/json' -Headers $h -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        $matched = @($resp.data.exactMatches)
        $modIds = @($matched | ForEach-Object { $_.id } | Select-Object -Unique)
        $names = @{}
        if ($modIds.Count -gt 0) {
            $mb = '{"modIds":[' + ($modIds -join ',') + ']}'
            $mr = Invoke-RestMethod -Uri 'https://api.curseforge.com/v1/mods' -Method Post -Body $mb -ContentType 'application/json' -Headers $h -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
            foreach ($m in @($mr.data)) { $names[[string]$m.id] = $m.name }
        }
        foreach ($m in $matched) {
            $fp = [uint32]$m.file.fileFingerprint
            if ($Fingerprints.ContainsKey($fp)) {
                $nm = $names[[string]$m.id]; if (-not $nm) { $nm = $m.file.displayName }
                $result[$Fingerprints[$fp]] = [pscustomobject]@{ Name = $nm; Version = $m.file.displayName }
            }
        }
    } catch { W ("  [!] " + (L 'CurseForge sorgusu başarısız' 'CurseForge query failed') + ": $($_.Exception.Message)") 'DarkYellow' }
    return $result
}

function Get-Megabase {
    param([string]$Hash)
    try {
        $r = Invoke-RestMethod -Uri "https://megabase.vercel.app/api/query?hash=$Hash" -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        if (-not $r.error -and $r.data -and $r.data.name) { return $r.data }
    } catch {}
    return $null
}

function Scan-Zip {
    param($Zip, [string]$Prefix, [int]$Depth, $R)
    foreach ($e in $Zip.Entries) {
        $name = $e.FullName
        if ($name.EndsWith('/')) { continue }
        $lower = $name.ToLowerInvariant()

        foreach ($sig in $ClientSignatures.Keys) {
            if ($lower.StartsWith($sig) -and -not $R.Clients.ContainsKey($ClientSignatures[$sig])) { $R.Clients[$ClientSignatures[$sig]] = "$Prefix$name" }
        }

        if ($lower.EndsWith('.class')) {
            $R.Classes++
            if ($Depth -eq 0) { $R.ClassSizes[$name] = $e.Length }
            $base = [System.IO.Path]::GetFileNameWithoutExtension($name)
            if ($base -cmatch '^[a-zA-Z]{1,2}(\$\d+)?$' -or $base -cmatch '^[Il1]{5,}$') { $R.ShortClasses++ }
            if ($name -match '[^\x20-\x7E]') { $R.WeirdNames++ }
            if ($e.Length -gt 0 -and $e.Length -lt 8MB) {
                $text = $Latin1.GetString((Read-EntryBytes $e))
                foreach ($m in $StrongRx.Matches($text)) { if (-not $R.Strong.ContainsKey($m.Value)) { $R.Strong[$m.Value] = "$Prefix$name" } }
                foreach ($m in $WeakRx.Matches($text))   { if (-not $R.Weak.ContainsKey($m.Value))   { $R.Weak[$m.Value]   = "$Prefix$name" } }
            }
        }
        elseif ($lower.EndsWith('.jar') -and $Depth -lt 3) {
            $ms = $null; $inner = $null
            try {
                $bytes = Read-EntryBytes $e
                $nh = Get-Sha1Hex $bytes
                if ($HashBlacklist.ContainsKey($nh)) { $R.Blacklisted.Add("$Prefix$name  ->  $($HashBlacklist[$nh])") }
                $ms = New-Object System.IO.MemoryStream(,$bytes)
                $inner = New-Object System.IO.Compression.ZipArchive($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                $R.Nested.Add("$Prefix$name")
                Scan-Zip $inner "$Prefix$name -> " ($Depth + 1) $R
            } catch {} finally { if ($inner) { $inner.Dispose() }; if ($ms) { $ms.Dispose() } }
        }
        elseif ($lower -match '\.(dll|exe|so|dylib|sys)$') { $R.Natives.Add("$Prefix$name") }
        elseif ($Depth -eq 0 -and $lower -match '^(fabric\.mod\.json|quilt\.mod\.json|meta-inf/(neoforge\.)?mods\.toml|meta-inf/manifest\.mf)$') {
            $meta = [System.Text.Encoding]::UTF8.GetString((Read-EntryBytes $e))
            if ($lower.EndsWith('manifest.mf')) {
                if (-not $R.MetaVersion -and $meta -match 'Implementation-Version:\s*(\S+)') { $R.MetaVersion = $matches[1] }
                continue
            }
            $R.HasMeta = $true
            if (-not $R.Loader) {
                switch -Regex ($lower) {
                    '^fabric\.mod\.json$'          { $R.Loader = 'fabric' }
                    '^quilt\.mod\.json$'           { $R.Loader = 'quilt' }
                    'neoforge\.mods\.toml$'        { $R.Loader = 'neoforge' }
                    '^meta-inf/mods\.toml$'         { $R.Loader = 'forge' }
                }
            }
            if (-not $R.ModId) {
                if ($meta -match '"id"\s*:\s*"([^"]+)"') { $R.ModId = $matches[1] } elseif ($meta -match 'modId\s*=\s*"([^"]+)"') { $R.ModId = $matches[1] }
            }
            if (-not $R.MetaName) {
                if ($meta -match '"name"\s*:\s*"([^"]+)"') { $R.MetaName = $matches[1] } elseif ($meta -match 'displayName\s*=\s*"([^"]+)"') { $R.MetaName = $matches[1] }
            }
            if ($meta -match '"version"\s*:\s*"([^"$]+)"' -or $meta -match '(?m)^\s*version\s*=\s*"([^"$]+)"') { $R.MetaVersion = $matches[1] }
        }
    }
}

function Analyze-Jar {
    param([string]$Path)
    $R = [pscustomobject]@{
        Classes = 0; ShortClasses = 0; WeirdNames = 0
        Strong = @{}; Weak = @{}; Clients = @{}; ClassSizes = @{}
        Nested = New-Object System.Collections.Generic.List[string]
        Natives = New-Object System.Collections.Generic.List[string]
        Blacklisted = New-Object System.Collections.Generic.List[string]
        ModId = $null; MetaName = $null; MetaVersion = $null; Loader = $null; HasMeta = $false; Error = $null
    }
    $zip = $null
    try { $zip = [System.IO.Compression.ZipFile]::OpenRead($Path); Scan-Zip $zip '' 0 $R }
    catch { $R.Error = $_.Exception.Message }
    finally { if ($zip) { $zip.Dispose() } }
    return $R
}

function Compare-WithOriginal {
    # Mod ID'si Modrinth'teki gerçek bir moda aitse orijinal dosyayı indirip class listesini karşılaştırır
    param($Res)
    $a = $Res.Analysis
    if (-not $a.ModId -or $a.ModId -match '^(minecraft|java|fabricloader|fabric|forge|neoforge|quilt_loader)$') { return }
    try { $proj = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$([uri]::EscapeDataString($a.ModId))" -Headers $ApiHeaders -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop }
    catch { return }
    if (-not $proj -or -not $proj.title) { return }

    $Res.FakeOf = $proj.title
    $Res.Flags.Add((L "SAHTE/DEĞİŞTİRİLMİŞ OLABİLİR: Mod ID '$($a.ModId)' Modrinth'teki '$($proj.title)' moduna ait ama dosya hash'i hiçbir resmi sürümle eşleşmiyor" "POSSIBLY FAKE/MODIFIED: mod ID '$($a.ModId)' belongs to '$($proj.title)' on Modrinth but the hash matches no official release"))

    if (-not $a.MetaVersion) { $Res.Flags.Add((L 'Orijinal sürüm belirlenemedi, class karşılaştırması yapılamadı' 'Original version unknown, class comparison skipped')); return }
    try { $vers = @(Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($proj.id)/version" -Headers $ApiHeaders -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop | ForEach-Object { $_ }) } catch { return }
    if ($a.Loader) { $byLoader = @($vers | Where-Object { @($_.loaders) -contains $a.Loader }); if ($byLoader.Count -gt 0) { $vers = $byLoader } }
    $exact = $true
    $mv   = $a.MetaVersion
    $core = ($mv -split '\+')[0]
    $ver = $vers | Where-Object { $_.version_number -eq $mv } | Select-Object -First 1
    if (-not $ver) { $ver = $vers | Where-Object { @($_.files | Where-Object { $_.filename -like "*$mv*" }).Count -gt 0 } | Select-Object -First 1 }
    if (-not $ver) { $exact = $false; $ver = $vers | Where-Object { $_.version_number -like "*$core*" } | Select-Object -First 1 }
    if (-not $ver) { $Res.Flags.Add((L "Modrinth'te '$($a.MetaVersion)' sürümü bulunamadı, class karşılaştırması yapılamadı" "Version '$($a.MetaVersion)' not found on Modrinth, class comparison skipped")); return }

    $file = @($ver.files | Where-Object { $_.primary }) | Select-Object -First 1
    if (-not $file) { $file = @($ver.files)[0] }
    if (-not $file -or $file.size -gt 40MB) { return }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("xtale_orig_" + [guid]::NewGuid().ToString('N') + '.jar')
    try {
        Invoke-WebRequest -Uri $file.url -OutFile $tmp -UseBasicParsing -Headers $ApiHeaders -TimeoutSec 60 -ErrorAction Stop
        $orig = @{}
        $z = [System.IO.Compression.ZipFile]::OpenRead($tmp)
        try { foreach ($e in $z.Entries) { if ($e.FullName.EndsWith('.class')) { $orig[$e.FullName] = $e.Length } } } finally { $z.Dispose() }

        $added   = @($a.ClassSizes.Keys | Where-Object { -not $orig.ContainsKey($_) } | Sort-Object)
        $changed = @($a.ClassSizes.Keys | Where-Object { $orig.ContainsKey($_) -and $orig[$_] -ne $a.ClassSizes[$_] } | Sort-Object)
        $removed = @($orig.Keys | Where-Object { -not $a.ClassSizes.ContainsKey($_) })
        $sameBuild = $exact -and ($removed.Count -le [Math]::Max(3, [int]($orig.Count * 0.05)))
        $Res.Diff = [pscustomobject]@{ Version = $ver.version_number; Added = $added; Changed = $changed; Removed = $removed.Count; SameBuild = $sameBuild }
        if (-not $sameBuild) { $Res.Flags.Add((L 'Orijinalle yapı farkı büyük, karşılaştırma sadece bilgi amaçlıdır' 'Build differs a lot from the original, comparison is informational only')) }
    } catch {} finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

# =====================================================================
#  Mod analizi
# =====================================================================
$allFiles   = @(Get-ChildItem -LiteralPath $mods -File -Force -Recurse)
$jarFiles   = @($allFiles | Where-Object { $_.Extension -eq '.jar' -and $_.DirectoryName -eq $mods })
$otherFiles = @($allFiles | Where-Object { $jarFiles -notcontains $_ })

$spinner = @('|', '/', '-', '\')
$results = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($f in $jarFiles) {
    $i++
    Write-Host ("`r  [{0}] {1}: {2} / {3}   " -f $spinner[$i % 4], (L 'Hash hesaplanıyor' 'Hashing'), $i, $jarFiles.Count) -ForegroundColor Yellow -NoNewline
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
    $results.Add([pscustomobject]@{
        File = $f; Hash = (Get-Sha1Hex $bytes); Fingerprint = [XtaleMA3]::Murmur2($bytes)
        Status = 'Unknown'; Source = $null; ModName = $null; Version = $null
        Zone = (Get-ZoneInfo $f.FullName); Flags = (New-Object System.Collections.Generic.List[string])
        Analysis = $null; FakeOf = $null; Diff = $null; Blacklist = $null
    })
}

Write-Host ("`r  " + (L 'Veritabanları sorgulanıyor...' 'Querying databases...') + (' ' * 40)) -ForegroundColor Yellow -NoNewline
$modrinth = Get-ModrinthBatch -Hashes @($results | ForEach-Object { $_.Hash })
$fpMap = @{}
foreach ($r in $results) { if (-not $modrinth.ContainsKey($r.Hash)) { $fpMap[[uint32]$r.Fingerprint] = $r.Hash } }
$curse = Get-CurseForgeBatch -Fingerprints $fpMap

$i = 0
foreach ($r in $results) {
    $i++
    Write-Host ("`r  [{0}] {1}: {2} / {3}   " -f $spinner[$i % 4], (L 'Mod analiz ediliyor' 'Analyzing mod'), $i, $results.Count) -ForegroundColor Yellow -NoNewline

    if ($HashBlacklist.ContainsKey($r.Hash)) {
        $r.Status = 'Cheat'; $r.Blacklist = $HashBlacklist[$r.Hash]
    } elseif ($modrinth.ContainsKey($r.Hash)) {
        $m = $modrinth[$r.Hash]; $r.Status = 'Verified'; $r.Source = 'Modrinth'; $r.ModName = $m.Name; $r.Version = $m.Version
    } elseif ($curse.ContainsKey($r.Hash)) {
        $m = $curse[$r.Hash]; $r.Status = 'Verified'; $r.Source = 'CurseForge'; $r.ModName = $m.Name; $r.Version = $null
    } else {
        $mb = Get-Megabase $r.Hash
        if ($mb) { $r.Status = 'Verified'; $r.Source = 'Megabase'; $r.ModName = $mb.name }
    }

    if ($mcStart -and $r.File.LastWriteTime -gt $mcStart) {
        $r.Flags.Add((L "Minecraft açıldıktan SONRA değiştirilmiş ($(Format-Date $r.File.LastWriteTime))" "Modified AFTER Minecraft started ($(Format-Date $r.File.LastWriteTime))"))
    }
    if ($r.Zone -and $r.Zone.HostUrl -and $r.Zone.HostUrl -match $SuspiciousHosts) {
        $r.Flags.Add((L 'Şüpheli kaynaktan indirilmiş' 'Downloaded from suspicious source') + ": $($r.Zone.HostUrl)")
    }
    if ($r.Status -eq 'Verified') { continue }

    $a = Analyze-Jar $r.File.FullName
    $r.Analysis = $a
    if (-not $r.ModName) { $r.ModName = if ($a.MetaName) { $a.MetaName } else { $a.ModId } }

    if ($a.Error)               { $r.Flags.Add((L 'Jar açılamadı (bozuk/şifreli olabilir)' 'Jar could not be opened (corrupt/encrypted?)') + ": $($a.Error)") }
    if ($a.Natives.Count -gt 0) { $r.Flags.Add((L 'Gömülü native dosya' 'Embedded native file') + ": $($a.Natives -join ', ')") }
    if ($a.WeirdNames -gt 0)    { $r.Flags.Add((L "$($a.WeirdNames) adet unicode/garip isimli class" "$($a.WeirdNames) classes with unicode/odd names")) }
    if ($a.Classes -ge 20 -and ($a.ShortClasses / $a.Classes) -ge 0.4) {
        $r.Flags.Add(((L 'Yüksek obfuscation: {0}/{1} class kısa isimli (%{2:N0})' 'Heavy obfuscation: {0}/{1} classes have short names ({2:N0}%)') -f $a.ShortClasses, $a.Classes, (100 * $a.ShortClasses / $a.Classes)))
    }
    if (-not $a.HasMeta -and -not $a.Error) { $r.Flags.Add((L 'Mod metadata dosyası yok (fabric.mod.json / mods.toml)' 'No mod metadata file (fabric.mod.json / mods.toml)')) }

    if ($r.Status -ne 'Cheat') { Compare-WithOriginal $r }

    if ($r.Status -eq 'Cheat' -or $a.Clients.Count -gt 0 -or $a.Strong.Count -gt 0 -or $a.Blacklisted.Count -gt 0 -or ($r.Diff -and $r.Diff.SameBuild -and $r.Diff.Added.Count -gt 0)) {
        $r.Status = 'Cheat'
    } elseif ($r.FakeOf) {
        $r.Status = 'Fake'
    } elseif ($r.Flags.Count -gt 0 -or $a.Weak.Count -gt 0) {
        $r.Status = 'Suspicious'
    }
}
Write-Host ("`r{0}`r" -f (' ' * 80)) -NoNewline

# =====================================================================
#  Mod sonuçları
# =====================================================================
$verified   = @($results | Where-Object Status -eq 'Verified')
$unknown    = @($results | Where-Object Status -eq 'Unknown')
$suspicious = @($results | Where-Object Status -eq 'Suspicious')
$fakes      = @($results | Where-Object Status -eq 'Fake')
$cheats     = @($results | Where-Object Status -eq 'Cheat')

function Show-Details {
    param($r)
    foreach ($fl in $r.Flags) { W "      [!] $fl" 'DarkYellow' }
    if ($r.Diff) {
        W ("      " + (L "Orijinal ($($r.Diff.Version)) ile karşılaştırma: $($r.Diff.Added.Count) eklenmiş, $($r.Diff.Changed.Count) değiştirilmiş, $($r.Diff.Removed) silinmiş class" "Compared to original ($($r.Diff.Version)): $($r.Diff.Added.Count) added, $($r.Diff.Changed.Count) changed, $($r.Diff.Removed) removed classes")) 'Magenta'
        foreach ($c in ($r.Diff.Added | Select-Object -First 15))   { W "        + $c" 'Red' }
        if ($r.Diff.Added.Count -gt 15) { W ("        ... +" + ($r.Diff.Added.Count - 15)) 'Red' }
        foreach ($c in ($r.Diff.Changed | Select-Object -First 10)) { W "        ~ $c" 'Yellow' }
        if ($r.Diff.Changed.Count -gt 10) { W ("        ... ~" + ($r.Diff.Changed.Count - 10)) 'Yellow' }
    }
    if ($r.Analysis -and $r.Analysis.Weak.Count -gt 0) {
        W ("      " + (L 'Zayıf stringler' 'Weak strings') + ": " + (($r.Analysis.Weak.Keys | Sort-Object) -join ', ')) 'DarkMagenta'
    }
    if ($r.Zone -and $r.Zone.HostUrl)     { W ("      " + (L 'İndirme' 'Download') + " : $($r.Zone.HostUrl)") 'DarkGray' }
    if ($r.Zone -and $r.Zone.ReferrerUrl) { W "      Referrer: $($r.Zone.ReferrerUrl)" 'DarkGray' }
}

function Show-Mod {
    param($r, [string]$Color)
    W ("  > {0,-40}" -f $r.File.Name) $Color -NoNewline
    W ("{0}  {1}" -f $r.ModName, (Format-Size $r.File.Length)) 'Gray'
    W "      SHA1: $($r.Hash)" 'DarkGray'
}

Section ((L 'DOĞRULANMIŞ MODLAR' 'VERIFIED MODS') + " ($($verified.Count))")
foreach ($r in $verified) {
    $label = if ($r.Version) { "$($r.ModName) $($r.Version)" } else { $r.ModName }
    W ("  > {0,-40}" -f $label) 'Green' -NoNewline
    W ("{0}  [{1}]" -f $r.File.Name, $r.Source) 'Gray'
    if ($r.Flags.Count -gt 0) { Show-Details $r }
}

Section ((L 'BİLİNMEYEN MODLAR' 'UNKNOWN MODS') + " ($($unknown.Count))")
foreach ($r in $unknown) { Show-Mod $r 'DarkYellow'; Show-Details $r }

Section ((L 'ŞÜPHELİ MODLAR' 'SUSPICIOUS MODS') + " ($($suspicious.Count))")
foreach ($r in $suspicious) { Show-Mod $r 'Yellow'; Show-Details $r }

Section ((L 'SAHTE / DEĞİŞTİRİLMİŞ MODLAR' 'FAKE / MODIFIED MODS') + " ($($fakes.Count))")
foreach ($r in $fakes) { Show-Mod $r 'Magenta'; Show-Details $r }

Section ((L 'HİLE TESPİT EDİLEN MODLAR' 'CHEAT MODS DETECTED') + " ($($cheats.Count))")
foreach ($r in $cheats) {
    Show-Mod $r 'Red'
    if ($r.Blacklist) { W ("      [" + (L 'BİLİNEN HİLE' 'KNOWN CHEAT') + "] $($r.Blacklist)") 'Red' }
    if ($r.Analysis) {
        foreach ($b in $r.Analysis.Blacklisted) { W ("      [" + (L 'BİLİNEN HİLE' 'KNOWN CHEAT') + "] $b") 'Red' }
        foreach ($c in $r.Analysis.Clients.Keys) { W "      [CLIENT] $c  ->  $($r.Analysis.Clients[$c])" 'Red' }
        foreach ($s in ($r.Analysis.Strong.Keys | Sort-Object)) { W ("      [STRING] {0,-18} ->  {1}" -f $s, $r.Analysis.Strong[$s]) 'Magenta' }
    }
    Show-Details $r
}

# =====================================================================
#  Mods klasörü, geri dönüşüm kutusu, son indirilenler
# =====================================================================
Section ((L 'MODS KLASÖRÜNDEKİ DİĞER DOSYALAR' 'OTHER FILES IN MODS FOLDER') + " ($($otherFiles.Count))")
foreach ($o in $otherFiles) {
    $rel = $o.FullName.Substring($mods.TrimEnd('\').Length).TrimStart('\')
    $col = if ($o.Name -match '\.(jar|disabled|zip|temp|tmp|bak|old)$|\.jar\.') { 'Yellow' } else { 'Gray' }
    W ("  > {0,-50} {1}  {2}" -f $rel, (Format-Size $o.Length), (Format-Date $o.LastWriteTime)) $col
}
if ($otherFiles.Count -eq 0) { Note (L 'Yok.' 'None.') }

Section (L 'GERİ DÖNÜŞÜM KUTUSU (.jar / .exe / .dll / .log)' 'RECYCLE BIN (.jar / .exe / .dll / .log)')
$binFound = 0
try {
    $shell = New-Object -ComObject Shell.Application
    $bin   = $shell.Namespace(10)
    foreach ($item in $bin.Items()) {
        if ($item.Path -match '\.(jar|exe|dll|log|gz|ahk)$' -or $item.Name -match '\.(jar|exe|dll|log|gz|ahk)$') {
            $binFound++
            $orig    = $bin.GetDetailsOf($item, 1)
            $deleted = ($bin.GetDetailsOf($item, 2)) -replace '[\u200E\u200F\u202A-\u202E]', ''
            $extra = ''
            if ($item.Path -match '\.jar$' -and (Test-Path -LiteralPath $item.Path)) {
                $hh = (Get-FileHash -LiteralPath $item.Path -Algorithm SHA1).Hash.ToLower()
                if ($HashBlacklist.ContainsKey($hh)) { $extra = "  [" + (L 'BİLİNEN HİLE' 'KNOWN CHEAT') + ": $($HashBlacklist[$hh])]" }
                else { $ba = Analyze-Jar $item.Path; if ($ba.Strong.Count -gt 0 -or $ba.Clients.Count -gt 0) { $extra = "  [" + (L 'HİLE' 'CHEAT') + ": " + ((@($ba.Clients.Keys) + @($ba.Strong.Keys)) -join ', ') + "]" } }
            }
            $col = if ($extra) { 'Red' } else { 'Yellow' }
            W ("  > {0,-40} {1}: {2}   {3}: {4}{5}" -f $item.Name, (L 'Konum' 'Location'), $orig, (L 'Silinme' 'Deleted'), $deleted, $extra) $col
            if ($extra) { $Script:SysFlags++ }
        }
    }
} catch {}
if ($binFound -eq 0) { Note (L 'İlgili silinmiş dosya bulunamadı.' 'No relevant deleted files found.') }

Section (L 'SON 7 GÜNDE GELEN .JAR DOSYALARI' '.JAR FILES FROM THE LAST 7 DAYS')
$recentFound = 0
$limit = (Get-Date).AddDays(-7)
$seenRecent = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($root in @((Join-Path $env:USERPROFILE 'Downloads'), (Join-Path $env:USERPROFILE 'Desktop'), (Join-Path $env:USERPROFILE 'Documents'), $env:TEMP)) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    foreach ($j in @(Get-ChildItem -LiteralPath $root -Filter *.jar -File -Recurse -Depth 3 -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $limit -or $_.CreationTime -gt $limit })) {
        if (-not $seenRecent.Add($j.FullName)) { continue }
        $recentFound++
        $hh = (Get-FileHash -LiteralPath $j.FullName -Algorithm SHA1).Hash.ToLower()
        $tag = ''
        if ($HashBlacklist.ContainsKey($hh)) { $tag = "  [" + (L 'BİLİNEN HİLE' 'KNOWN CHEAT') + ": $($HashBlacklist[$hh])]" }
        elseif ($j.Length -lt 50MB) { $ja = Analyze-Jar $j.FullName; if ($ja.Strong.Count -gt 0 -or $ja.Clients.Count -gt 0) { $tag = "  [" + (L 'HİLE' 'CHEAT') + ": " + ((@($ja.Clients.Keys) + @($ja.Strong.Keys)) -join ', ') + "]" } }
        $z = Get-ZoneInfo $j.FullName
        W ("  > {0}  {1}{2}" -f $j.FullName, (Format-Date $j.LastWriteTime), $tag) $(if ($tag) { 'Red' } else { 'Yellow' })
        if ($tag) { $Script:SysFlags++ }
        if ($z -and $z.HostUrl) { W ("      " + (L 'İndirme' 'Download') + ": $($z.HostUrl)") 'DarkGray' }
    }
}
if ($recentFound -eq 0) { Note (L 'Son 7 günde .jar dosyası bulunamadı.' 'No .jar files in the last 7 days.') }

# =====================================================================
#  Minecraft log kontrolü
# =====================================================================
Section (L 'MINECRAFT LOG KONTROLÜ' 'MINECRAFT LOG CHECK')
$logDir = Join-Path $mcRoot 'logs'
if (-not (Test-Path -LiteralPath $logDir)) {
    Warn ((L 'Logs klasörü yok' 'Logs folder missing') + ": $logDir")
} else {
    $latest = Get-Item -LiteralPath (Join-Path $logDir 'latest.log') -Force -ErrorAction SilentlyContinue
    if (-not $latest) {
        if ($mcPids.Count -gt 0) { Warn (L 'Minecraft açık ama latest.log yok (silinmiş olabilir)' 'Minecraft is running but latest.log is missing (possibly deleted)') }
        else { Note (L 'latest.log bulunamadı.' 'latest.log not found.') }
    } else {
        W ("  latest.log: {0}  {1}: {2}  {3}: {4}" -f (Format-Size $latest.Length), (L 'Oluşturma' 'Created'), (Format-Date $latest.CreationTime), (L 'Değişiklik' 'Modified'), (Format-Date $latest.LastWriteTime)) 'Gray'
        if ($mcStart) {
            if ($latest.CreationTime -gt $mcStart.AddMinutes(3)) { Warn (L 'latest.log oyun açıldıktan sonra yeniden oluşturulmuş (silinip yeniden yazılmış olabilir)' 'latest.log was recreated after the game started (possibly deleted and rewritten)') }
            $up = ((Get-Date) - $mcStart).TotalMinutes
            if ($up -gt 10 -and $latest.Length -lt 2KB) { Warn (L 'Oyun uzun süredir açık ama latest.log çok küçük (temizlenmiş olabilir)' 'Game has been running for a while but latest.log is tiny (possibly cleared)') }
            $firstLine = Get-Content -LiteralPath $latest.FullName -TotalCount 1 -ErrorAction SilentlyContinue
            if ($firstLine -match '^\[(\d{2}):(\d{2}):(\d{2})') {
                $logStart = $mcStart.Date.AddHours([int]$matches[1]).AddMinutes([int]$matches[2]).AddSeconds([int]$matches[3])
                if ([math]::Abs(($logStart - $mcStart).TotalMinutes) -gt 5 -and [math]::Abs(($logStart - $mcStart).TotalMinutes) -lt 1435) {
                    Warn ((L "latest.log ilk satır saati ($($logStart.ToString('HH:mm:ss'))) oyun başlangıcıyla ($($mcStart.ToString('HH:mm:ss'))) uyuşmuyor" "latest.log first line time ($($logStart.ToString('HH:mm:ss'))) does not match game start ($($mcStart.ToString('HH:mm:ss')))"))
                }
            }
        }
    }

    $gz = @(Get-ChildItem -LiteralPath $logDir -Filter '*.log.gz' -File -Force | Sort-Object Name)
    W ("  " + (L "Arşiv log sayısı: $($gz.Count)" "Archived logs: $($gz.Count)")) 'Gray'
    $byDay = @{}
    foreach ($g in $gz) {
        if ($g.Name -match '^(\d{4}-\d{2}-\d{2})-(\d+)\.log\.gz$') {
            if (-not $byDay.ContainsKey($matches[1])) { $byDay[$matches[1]] = New-Object System.Collections.Generic.List[int] }
            $byDay[$matches[1]].Add([int]$matches[2])
        }
    }
    foreach ($day in ($byDay.Keys | Sort-Object)) {
        $nums = @($byDay[$day] | Sort-Object)
        $missing = @(1..($nums[-1]) | Where-Object { $nums -notcontains $_ })
        if ($missing.Count -gt 0) { Warn ((L "$day tarihli loglarda eksik numara var: $($missing -join ', ') (log silinmiş)" "Missing log numbers on ${day}: $($missing -join ', ') (log deleted)")) }
    }
    foreach ($g in ($gz | Sort-Object LastWriteTime -Descending | Select-Object -First 5)) {
        W ("    {0,-28} {1}" -f $g.Name, (Format-Date $g.LastWriteTime)) 'DarkGray'
    }
    if ($gz.Count -gt 0 -and $bootTime) {
        $newest = ($gz | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
        if (((Get-Date) - $newest).TotalDays -gt 14 -and $mcPids.Count -gt 0) { Note (L 'Son arşiv log 14 günden eski. Oyuncu uzun süredir oynamıyor veya loglar temizlenmiş olabilir.' 'Newest archived log is older than 14 days. Player may not play often or logs were cleared.') }
    }
}

# =====================================================================
#  Prefetch
# =====================================================================
Section 'PREFETCH'
$pfDir = Join-Path $env:SystemRoot 'Prefetch'
try {
    $enPf = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -ErrorAction Stop).EnablePrefetcher
    if ($enPf -eq 0) { Warn (L 'Prefetch kapatılmış (EnablePrefetcher = 0)' 'Prefetch is disabled (EnablePrefetcher = 0)') }
} catch {}
if (-not $isAdmin) {
    Note (L 'Prefetch için yönetici izni gerekli.' 'Administrator required for Prefetch.')
} elseif (Test-Path -LiteralPath $pfDir) {
    $pfs = @(Get-ChildItem -LiteralPath $pfDir -Filter *.pf -File -Force)
    W ("  " + (L "Toplam .pf dosyası: $($pfs.Count)" "Total .pf files: $($pfs.Count)")) 'Gray'
    if ($pfs.Count -gt 0) {
        $oldest = ($pfs | Sort-Object CreationTime | Select-Object -First 1).CreationTime
        W ("  " + (L 'En eski kayıt' 'Oldest entry') + ": $(Format-Date $oldest)") 'Gray'
        if ($pfs.Count -lt 40 -or ($bootTime -and $oldest -gt $bootTime)) { Warn (L 'Prefetch kayıtları çok az veya açılıştan yeni. Yakın zamanda temizlenmiş olabilir' 'Very few Prefetch entries or all newer than boot. Possibly cleared recently') }
    } else { Warn (L 'Prefetch klasörü boş' 'Prefetch folder is empty') }

    foreach ($pf in ($pfs | Where-Object { (($_.Attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) -or (($_.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) })) {
        Warn ((L 'Salt okunur/gizli .pf dosyası (bypass yöntemi)' 'Read-only/hidden .pf file (bypass technique)') + ": $($pf.Name)")
    }
    foreach ($pf in $pfs) {
        $exe = $pf.Name -replace '-[0-9A-F]{8}\.pf$', ''
        if ($ProcRx.IsMatch([IO.Path]::GetFileNameWithoutExtension($exe))) {
            Warn ("{0}  {1}: {2}" -f $exe, (L 'son çalışma' 'last run'), (Format-Date $pf.LastWriteTime))
        }
    }
    $since = if ($mcStart) { $mcStart } elseif ($bootTime) { $bootTime } else { (Get-Date).AddHours(-3) }
    $recentPf = @($pfs | Where-Object { $_.LastWriteTime -gt $since } | Sort-Object LastWriteTime -Descending)
    W ("  " + (L "$(Format-Date $since) sonrası çalıştırılan programlar ($($recentPf.Count)):" "Programs run since $(Format-Date $since) ($($recentPf.Count)):")) 'White'
    foreach ($pf in ($recentPf | Select-Object -First 40)) {
        W ("    {0,-40} {1}" -f ($pf.Name -replace '-[0-9A-F]{8}\.pf$', ''), (Format-Date $pf.LastWriteTime)) 'DarkGray'
    }
}

# =====================================================================
#  BAM (Background Activity Moderator)
# =====================================================================
Section 'BAM'
$devMap = @{}
foreach ($d in [IO.DriveInfo]::GetDrives()) {
    $l = $d.Name.TrimEnd('\'); $dev = [XtaleMA3]::DosDevice($l)
    if ($dev) { $devMap[$dev] = $l }
}
function Convert-DevicePath { param([string]$P)
    foreach ($k in $devMap.Keys) { if ($P.StartsWith($k + '\', 'OrdinalIgnoreCase')) { return $devMap[$k] + $P.Substring($k.Length) } }
    return $P
}
$bamFound = 0
if (-not $isAdmin) { Note (L 'BAM için yönetici izni gerekli.' 'Administrator required for BAM.') }
else {
    $bamSince = if ($bootTime) { $bootTime } else { (Get-Date).AddDays(-1) }
    foreach ($root in @('HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings')) {
        if (-not (Test-Path $root)) { continue }
        foreach ($sidKey in @(Get-ChildItem $root)) {
            $key = Get-Item $sidKey.PSPath
            $entries = foreach ($vn in $key.GetValueNames()) {
                if ($vn -notmatch '\\') { continue }
                $data = $key.GetValue($vn)
                if (-not ($data -is [byte[]]) -or $data.Length -lt 8) { continue }
                $t = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($data, 0)).ToLocalTime()
                if ($t -lt $bamSince) { continue }
                [pscustomobject]@{ Path = (Convert-DevicePath $vn); Time = $t }
            }
            foreach ($en in ($entries | Sort-Object Time -Descending)) {
                $bamFound++
                $exists = Test-Path -LiteralPath $en.Path
                $sig = ''
                if ($exists -and $en.Path -match '\.exe$' -and $en.Path -notmatch '\\Windows\\') {
                    $st = (Get-AuthenticodeSignature -LiteralPath $en.Path -ErrorAction SilentlyContinue).Status
                    if ($st -and $st -ne 'Valid') { $sig = "  [" + (L 'İMZASIZ' 'UNSIGNED') + ": $st]" }
                }
                $del = if (-not $exists) { "  [" + (L 'SİLİNMİŞ' 'DELETED') + "]" } else { '' }
                $susp = $ProcRx.IsMatch([IO.Path]::GetFileNameWithoutExtension($en.Path))
                $line = ("  {0}  {1}{2}{3}" -f (Format-Date $en.Time), $en.Path, $del, $sig)
                if ($susp) { Warn $line.Trim() }
                elseif ($del) { W $line 'Yellow' }
                elseif ($sig) { W $line 'DarkYellow' }
                else { W $line 'DarkGray' }
            }
        }
    }
    if ($bamFound -eq 0) { Note (L 'Açılıştan beri BAM kaydı yok.' 'No BAM entries since boot.') }
}

# =====================================================================
#  UserAssist
# =====================================================================
Section 'USERASSIST'
function Convert-Rot13 { param([string]$s)
    $c = $s.ToCharArray()
    for ($k = 0; $k -lt $c.Length; $k++) {
        $ch = [int]$c[$k]
        if ($ch -ge 65 -and $ch -le 90) { $c[$k] = [char]((($ch - 65 + 13) % 26) + 65) }
        elseif ($ch -ge 97 -and $ch -le 122) { $c[$k] = [char]((($ch - 97 + 13) % 26) + 97) }
    }
    return -join $c
}
$knownFolders = @{
    '{6D809377-6AF0-444B-8957-A3773F02200E}' = $env:ProgramFiles
    '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' = ${env:ProgramFiles(x86)}
    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' = (Join-Path $env:SystemRoot 'System32')
    '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' = $env:SystemRoot
    '{374DE290-123F-4565-9164-39C4925E467B}' = (Join-Path $env:USERPROFILE 'Downloads')
    '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}' = (Join-Path $env:USERPROFILE 'Desktop')
}
$uaSince = (Get-Date).AddDays(-1)
$uaFound = 0
$uaRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
foreach ($guidKey in @(Get-ChildItem $uaRoot -ErrorAction SilentlyContinue)) {
    $countKey = Get-Item (Join-Path $guidKey.PSPath 'Count') -ErrorAction SilentlyContinue
    if (-not $countKey) { continue }
    $rows = foreach ($vn in $countKey.GetValueNames()) {
        $data = $countKey.GetValue($vn)
        if (-not ($data -is [byte[]]) -or $data.Length -lt 68) { continue }
        $ft = [BitConverter]::ToInt64($data, 60)
        if ($ft -le 0) { continue }
        $t = [DateTime]::FromFileTimeUtc($ft).ToLocalTime()
        if ($t -lt $uaSince) { continue }
        $nm = Convert-Rot13 $vn
        foreach ($g in $knownFolders.Keys) { if ($nm.StartsWith($g, 'OrdinalIgnoreCase')) { $nm = $knownFolders[$g] + $nm.Substring($g.Length) } }
        [pscustomobject]@{ Name = $nm; Time = $t; Count = [BitConverter]::ToInt32($data, 4) }
    }
    foreach ($row in ($rows | Sort-Object Time -Descending)) {
        $uaFound++
        $line = ("  {0}  x{1,-4} {2}" -f (Format-Date $row.Time), $row.Count, $row.Name)
        $exists = ($row.Name -notmatch '^[A-Z]:\\') -or (Test-Path -LiteralPath $row.Name)
        if ($ProcRx.IsMatch([IO.Path]::GetFileNameWithoutExtension($row.Name))) { Warn $line.Trim() }
        elseif (-not $exists) { W ($line + "  [" + (L 'SİLİNMİŞ' 'DELETED') + "]") 'Yellow' }
        else { W $line 'DarkGray' }
    }
}
if ($uaFound -eq 0) { Note (L 'Son 24 saatte UserAssist kaydı yok.' 'No UserAssist entries in the last 24 hours.') }

# =====================================================================
#  Macro yazılımları
# =====================================================================
Section (L 'MACRO YAZILIMLARI' 'MACRO SOFTWARE')
$macroSoft = [ordered]@{
    'Logitech G HUB'         = @("$env:LOCALAPPDATA\LGHUB")
    'Logitech Gaming Software' = @("$env:LOCALAPPDATA\Logitech\Logitech Gaming Software")
    'Razer Synapse'          = @("$env:LOCALAPPDATA\Razer\Synapse3", "$env:ProgramData\Razer\Synapse3", "$env:LOCALAPPDATA\Razer\RazerAppEngine")
    'Corsair iCUE'           = @("$env:APPDATA\Corsair\CUE5", "$env:APPDATA\Corsair\CUE4", "$env:APPDATA\Corsair\CUE")
    'SteelSeries GG'         = @("$env:ProgramData\SteelSeries\GG", "$env:ProgramData\SteelSeries\SteelSeries Engine 3")
    'Bloody'                 = @("${env:ProgramFiles(x86)}\Bloody7", "$env:ProgramFiles\Bloody7")
    'HyperX NGENUITY'        = @("$env:LOCALAPPDATA\Packages\HyperX.NGENUITY_*")
    'Glorious Core'          = @("$env:APPDATA\Glorious Core", "$env:LOCALAPPDATA\Glorious")
    'ASUS Armoury Crate'     = @("$env:ProgramData\ASUS\ARMOURY CRATE Service")
    'AutoHotkey'             = @("$env:ProgramFiles\AutoHotkey", "$env:USERPROFILE\Documents\AutoHotkey")
}
$macroAny = $false
$macroSince = if ($mcStart) { $mcStart } else { (Get-Date).AddHours(-3) }
foreach ($soft in $macroSoft.Keys) {
    foreach ($pattern in $macroSoft[$soft]) {
        foreach ($dir in @(Get-Item -Path $pattern -Force -ErrorAction SilentlyContinue)) {
            if (-not $dir.PSIsContainer) { continue }
            $macroAny = $true
            $files = @(Get-ChildItem -LiteralPath $dir.FullName -File -Recurse -Depth 5 -Force -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 30MB })
            $macroFiles = @($files | Where-Object { $_.Name -match 'macro|\.amc$|\.mgp$|\.ahk$' })
            $contentHits = 0
            foreach ($cf in @($files | Where-Object { $_.Name -match '^settings\.(db|json)$|\.xml$|profile' } | Select-Object -First 50)) {
                try { $txt = $Latin1.GetString([IO.File]::ReadAllBytes($cf.FullName)); $contentHits += ([regex]::Matches($txt, '(?i)"?macro')).Count } catch {}
            }
            $lastMod = ($files | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
            W ("  > {0,-26} {1}" -f $soft, $dir.FullName) 'White'
            W ("      " + (L "Macro dosyası: $($macroFiles.Count)   İçerikte 'macro' geçişi: $contentHits   Son değişiklik: $(Format-Date $lastMod)" "Macro files: $($macroFiles.Count)   'macro' mentions: $contentHits   Last modified: $(Format-Date $lastMod)")) 'Gray'
            $recentMacro = @($files | Where-Object { $_.LastWriteTime -gt $macroSince -and ($_.Name -match 'macro|\.amc$|\.mgp$|\.ahk$|settings\.db|\.xml$') })
            foreach ($rm in ($recentMacro | Select-Object -First 10)) {
                Warn ((L 'Oyun sırasında değiştirilmiş' 'Modified during gameplay') + ": $($rm.FullName)  $(Format-Date $rm.LastWriteTime)")
            }
        }
    }
}
$ahk = @(foreach ($root in @((Join-Path $env:USERPROFILE 'Desktop'), (Join-Path $env:USERPROFILE 'Downloads'), (Join-Path $env:USERPROFILE 'Documents'))) {
    Get-ChildItem -LiteralPath $root -Include *.ahk, *.amc -File -Recurse -Depth 3 -Force -ErrorAction SilentlyContinue
})
foreach ($a in $ahk) { W ("  > {0}  {1}" -f $a.FullName, (Format-Date $a.LastWriteTime)) 'Yellow' }
if (-not $macroAny -and $ahk.Count -eq 0) { Note (L 'Bilinen macro yazılımı bulunamadı.' 'No known macro software found.') }

# =====================================================================
#  USN Journal (silinen dosyalar)
# =====================================================================
Section (L 'USN JOURNAL - SİLİNEN DOSYALAR' 'USN JOURNAL - DELETED FILES')
if (-not $doUsn) {
    Note (L 'Atlandı.' 'Skipped.')
} else {
    Write-Host ("  " + (L 'USN Journal okunuyor, lütfen bekleyin...' 'Reading USN Journal, please wait...')) -ForegroundColor Yellow
    $drive = $env:SystemDrive
    $lines = @(cmd /c "fsutil usn readjournal $drive csv | findstr /i /l /c:.jar /c:.exe /c:.dll /c:.ahk /c:latest.log /c:.log.gz /c:.pf" 2>$null)
    $hdr = 0..20 | ForEach-Object { "c$_" }
    $usnSince = (Get-Date).AddDays(-2)
    $deletedRows = New-Object System.Collections.Generic.List[object]
    foreach ($ln in $lines) {
        $row = $ln | ConvertFrom-Csv -Header $hdr
        if (-not $row -or -not $row.c3) { continue }
        $reason = 0
        try { $reason = [Convert]::ToInt64(($row.c3.Trim().Trim('"') -replace '^0x', ''), 16) } catch { continue }
        if (($reason -band 0x200) -eq 0) { continue }
        $name = $row.c1.Trim().Trim('"')
        $row.c5 = ([string]$row.c5).Trim().Trim('"')
        if ($name -notmatch '(?i)\.(jar|exe|dll|ahk|pf)$|^latest\.log$|\.log\.gz$') { continue }
        $t = $null; [datetime]::TryParse($row.c5, [ref]$t) | Out-Null
        if ($t -and $t -lt $usnSince) { continue }
        $deletedRows.Add([pscustomobject]@{ Name = $name; Time = $t; Raw = $row.c5 })
    }
    $uniq = @($deletedRows | Sort-Object Name, Time -Unique | Sort-Object Time -Descending)
    W ("  " + (L "Son 48 saatte silinen ilgili dosya: $($uniq.Count)" "Relevant files deleted in the last 48 hours: $($uniq.Count)")) 'Gray'
    foreach ($d in ($uniq | Select-Object -First 80)) {
        $ts = if ($d.Time) { Format-Date $d.Time } else { $d.Raw }
        $line = "  $ts  $($d.Name)"
        if ($d.Name -match '(?i)\.jar$|latest\.log|\.log\.gz$|\.pf$' -or $ProcRx.IsMatch([IO.Path]::GetFileNameWithoutExtension($d.Name))) { Warn $line.Trim() }
        else { W $line 'DarkGray' }
    }
    if ($uniq.Count -gt 80) { Note (L "... ve $($uniq.Count - 80) kayıt daha" "... and $($uniq.Count - 80) more") }
}

# =====================================================================
#  Bellek taraması
# =====================================================================
Section (L 'MINECRAFT BELLEK TARAMASI' 'MINECRAFT MEMORY SCAN')
if (-not $doMem) {
    Note (L 'Atlandı.' 'Skipped.')
} else {
    $strongPart = @($StrongStrings | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $clientPart = @($ClientSignatures.Keys | Where-Object { $_.Trim('/').Contains('/') } | ForEach-Object { [regex]::Escape($_.TrimEnd('/')) -replace '/', '[/.]' }) -join '|'
    $memRx = '(' + $strongPart + '|(?i:' + $clientPart + '))'
    foreach ($procId in $mcPids) {
        Write-Host ("  " + (L "PID $procId taranıyor, lütfen bekleyin..." "Scanning PID $procId, please wait...")) -ForegroundColor Yellow
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $hits = [XtaleMA3]::ScanProcess([int]$procId, $memRx, [long]($Config.MemoryScanMaxGB * 1GB))
        $sw.Stop()
        if ($null -eq $hits) { W ("  " + (L "PID $procId açılamadı (yönetici olarak deneyin)." "Could not open PID $procId (try as administrator).")) 'DarkYellow'; continue }
        W ("  PID {0}: {1} {2}, {3:N0} sn" -f $procId, (Format-Size ([XtaleMA3]::LastScanned)), (L 'tarandı' 'scanned'), $sw.Elapsed.TotalSeconds) 'Gray'
        if ($hits.Count -eq 0) { Note (L 'Bellekte hile stringi bulunamadı.' 'No cheat strings found in memory.') }
        foreach ($k in ($hits.Keys | Sort-Object)) { Warn ("{0}  x{1}" -f $k, $hits[$k]) }
    }
    Note (L 'Bellek bulguları sohbet/sunucu mesajlarından da gelebilir, mutlaka manuel doğrulayın.' 'Memory hits can come from chat/server messages too, always verify manually.')
}

# =====================================================================
#  Özet ve rapor
# =====================================================================
Section (L 'ÖZET' 'SUMMARY')
W ("  {0,-22}: {1}" -f (L 'Toplam mod' 'Total mods'), $results.Count) 'White'
W ("  {0,-22}: {1}" -f (L 'Doğrulanmış' 'Verified'), $verified.Count) 'Green'
W ("  {0,-22}: {1}" -f (L 'Bilinmeyen' 'Unknown'), $unknown.Count) 'DarkYellow'
W ("  {0,-22}: {1}" -f (L 'Şüpheli' 'Suspicious'), $suspicious.Count) 'Yellow'
W ("  {0,-22}: {1}" -f (L 'Sahte / değiştirilmiş' 'Fake / modified'), $fakes.Count) 'Magenta'
W ("  {0,-22}: {1}" -f (L 'Hile tespit' 'Cheats detected'), $cheats.Count) 'Red'
W ("  {0,-22}: {1}" -f (L 'Sistem uyarısı' 'System warnings'), $Script:SysFlags) 'Red'
W
if ($cheats.Count -gt 0) {
    W ('  ' + (L 'SONUÇ: Hile içeren mod tespit edildi. Bulguları manuel olarak doğrulayın.' 'RESULT: Cheat mod detected. Verify the findings manually.')) 'Red'
} elseif ($fakes.Count -gt 0 -or $suspicious.Count -gt 0 -or $Script:SysFlags -gt 0) {
    W ('  ' + (L 'SONUÇ: Şüpheli bulgular var. Recaf / JD-GUI ve manuel SS ile inceleyin.' 'RESULT: Suspicious findings. Inspect with Recaf / JD-GUI and a manual SS.')) 'Yellow'
} else {
    W ('  ' + (L 'SONUÇ: Açık bir hile bulgusu yok.' 'RESULT: No obvious cheat findings.')) 'Green'
}
W
W ('-' * 72) 'DarkGray'
W '  Made by ' 'DarkGray' -NoNewline
W 'XTALE' 'Red' -NoNewline
W '  |  Discord: ' 'DarkGray' -NoNewline
W 'discord.gg/njvChGfE9P' 'Cyan'
W ('-' * 72) 'DarkGray'

$outDir = 'C:\ScreenShare'
try { if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force -ErrorAction Stop | Out-Null } } catch { $outDir = $env:TEMP }
$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$txtFile = Join-Path $outDir "ModAnalyzer_$stamp.txt"
$htmFile = Join-Path $outDir "ModAnalyzer_$stamp.html"

$Script:Recording = $false
try {
    $Script:Report | Set-Content -LiteralPath $txtFile -Encoding UTF8 -ErrorAction Stop
    $html = @"
<!DOCTYPE html>
<html lang="$($Script:Lang)"><head><meta charset="utf-8"><title>Mod Analyzer - $env:COMPUTERNAME - $stamp</title>
<style>
body{background:#0d1117;margin:0;padding:24px;font-family:Consolas,'Cascadia Mono',monospace;font-size:13px}
.wrap{max-width:1200px;margin:0 auto;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;overflow-x:auto}
pre{margin:0;white-space:pre-wrap;word-break:break-all;line-height:1.45}
.top{color:#7d8590;margin-bottom:12px}.top a{color:#3bc9db}
</style></head><body><div class="wrap">
<div class="top">Mod Analyzer v$ScriptVersion &middot; Made by <b style="color:#ff6b6b">XTALE</b> &middot; <a href="https://discord.gg/njvChGfE9P">discord.gg/njvChGfE9P</a></div>
<pre>$($Script:Html.ToString())</pre></div></body></html>
"@
    Set-Content -LiteralPath $htmFile -Value $html -Encoding UTF8 -ErrorAction Stop
    W
    W ("  " + (L 'Rapor kaydedildi' 'Report saved') + ":") 'Cyan'
    W "    $txtFile" 'White'
    W "    $htmFile" 'White'
} catch {
    W ("  " + (L 'Rapor kaydedilemedi' 'Report could not be saved') + ": $($_.Exception.Message)") 'Red'
}
try { if (Test-Path -LiteralPath $htmFile) { Start-Process $htmFile -ErrorAction Stop } } catch {}
W
