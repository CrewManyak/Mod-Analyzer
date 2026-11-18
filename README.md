# XTALE Mod Analyzer v3.0.0

Made by **XTALE** · Discord: [discord.gg/njvChGfE9P](https://discord.gg/njvChGfE9P)

Minecraft screenshare için gelişmiş mod ve sistem analiz aracı.

## Dosyalar

| Dosya | Ne işe yarar |
|---|---|
| `ModAnalyzer.ps1` | Ana script |
| `signatures.json` | Uzaktan güncellenebilen hile listesi ve hash kara listesi |
| `version.txt` | Sürüm kontrolü için güncel sürüm numarası |

## Kurulum (tek seferlik)

1. GitHub'da yeni bir **public** repo aç (örnek: `XTALE-ModAnalyzer`).
2. Üç dosyayı da repoya yükle. `ModAnalyzer.ps1` dosyasını yüklerken kodlamasını değiştirme.
3. Her dosyayı açıp **Raw** butonuna bas ve linki kopyala. Linkler şöyle görünür:
   `[https://raw.githubusercontent.com/KULLANICI/XTALE-ModAnalyzer/main/ModAnalyzer.ps1](https://github.com/CrewManyak/Mod-Analyzer/blob/main/ModAnalyzer.ps1)`
4. `ModAnalyzer.ps1` dosyasının en üstündeki `$Config` kısmını doldur:
   - `SignaturesUrl` → `signatures.json` dosyasının raw linki
   - `VersionUrl` → `version.txt` dosyasının raw linki
   - `CurseForgeApiKey` → [console.curseforge.com](https://console.curseforge.com) adresinden ücretsiz alınan anahtar (istersen boş bırak)
5. Değişikliği GitHub'a kaydet.

## Çalıştırma

PowerShell'i **yönetici olarak** aç ve şunu yapıştır (RAW_LINK yerine `ModAnalyzer.ps1` dosyasının raw linkini yaz):

```powershell
powershell -ExecutionPolicy Bypass -Command "iex ((irm 'RAW_LINK').TrimStart([char]0xFEFF))"
```

Dosya bilgisayardaysa şu komutu kullan:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & "C:\dosyanın\yolu\ModAnalyzer.ps1"
```

Raporlar `C:\ScreenShare` klasörüne `.txt` ve `.html` olarak kaydedilir. HTML rapor tarama bitince otomatik açılır.

## Hile listesini güncelleme

Scripti tekrar dağıtmana gerek yok. GitHub'da `signatures.json` dosyasını düzenlemen yeterli:

- `strong` → bulunursa mod **Hile** sayılır
- `weak` → bulunursa mod **Şüpheli** sayılır
- `processes` → Prefetch, BAM, UserAssist ve çalışan süreçlerde aranan program isimleri
- `clients` → hile client paket yolları (`"paket/yolu/": "Client Adı"`)
- `hashes` → yakalanmış hile jar'larının SHA1 hash'leri (`"hash": "açıklama"`)

Yakalanan bir hile jar'ının hash'i rapordaki `SHA1:` satırında yazar. Bu hash'i `hashes` kısmına eklersen aynı dosya bir daha anında **Bilinen hile** olarak çıkar.

## Yeni sürüm yayınlama

1. `ModAnalyzer.ps1` içindeki `$ScriptVersion` değerini artır (örnek: `3.0.1`).
2. `version.txt` dosyasına aynı numarayı yaz.

Eski sürümü kullanan yetkililer script açılırken "Yeni sürüm mevcut" uyarısı görür.

## Kontrol edilenler

- Modrinth, CurseForge ve Megabase üzerinden hash doğrulaması
- Hash kara listesi (iç içe jar'lar dahil)
- Class içi hile string taraması, hile client imzaları, obfuscation, gömülü .dll/.exe
- Sahte mod tespiti (gerçek bir modun ID'sini taşıyan ama hash'i tutmayan jar'lar)
- Değiştirilmiş mod tespiti (orijinal dosya Modrinth'ten indirilir, eklenen/değişen class'lar listelenir)
- Minecraft süreçleri, uptime, `-javaagent` enjeksiyonu
- Çalışan şüpheli süreçler
- Mods klasöründeki diğer dosyalar, Geri Dönüşüm Kutusu, son 7 günün .jar dosyaları
- Minecraft log silme kontrolü (latest.log zamanı, eksik log numaraları)
- Prefetch (temizlenme, salt okunur .pf bypass'ı, oyun sırasında çalışan programlar)
- BAM (silinmiş ve imzasız programlar)
- UserAssist (son 24 saat)
- Macro yazılımları (Logitech, Razer, Corsair, SteelSeries, Bloody, HyperX, Glorious, ASUS, AutoHotkey)
- USN Journal'da son 48 saatte silinen dosyalar (isteğe bağlı)
- Minecraft belleğinde hile stringi taraması (isteğe bağlı)
- Türkçe / İngilizce dil desteği

## Not

Bulgular otomatik bir karar değildir. Ban vermeden önce bulguları Recaf, JD-GUI veya manuel SS ile doğrulayın.
