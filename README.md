#  SReporT - Security Scan Reporting Tool  

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)
![Last Commit](https://img.shields.io/github/last-commit/1onurakcay1/SReporT)

**Versiyon:** 1.0  
**Yazar:** Onur Muhammet AKÇAY  


SReporT, güvenlik tarama çıktılarınızı bir HTML raporuna dönüştüren Python tabanlı bir araçtır.  
Responsive tasarımı ve PDF export özelliği ile tarama sonuçlarını profesyonelce sunmanıza yardımcı olur.  

---

##  Özellikler
- 📊 Host, port, servis, işletim sistemi ve script çıktıları raporlar.  
- 🎨 Modern HTML template kullanır.  
- 🧮 Toplam istatistikleri (host, port, servis, script) hesaplar.  
- 📑 PDF export desteği.    

---

## 🚀 Kurulum

Python 3.8+ sürümü gereklidir.  
Ekstra kütüphane kurulumu gerekmez (sadece Python’un standart kütüphaneleri kullanır).

```bash
git clone https://github.com/1onurakcay1/SReporT.git
cd SReporT
```
##  Komut Satırı Parametreleri

SReporT aracı şu parametreleri destekler:

| Parametre | Zorunlu | Açıklama |
|-----------|---------|----------|
| `-i`, `--input`    |  Evet | Nmap çıktı dosyası. Desteklenen formatlar: `.xml`, `.gnmap`, `.txt`, `.nmap` |
| `-o`, `--output`   |  Hayır | Oluşturulacak HTML rapor dosyası. Varsayılan: **sonuc.html** |
| `-t`, `--template` |  Hayır | Kullanılacak HTML şablon dosyası. Varsayılan: **template.html** |

---

###  Kullanım Örnekleri

**Zorunlu parametre (`-i`) ile:**
```bash
python3 SReporT.py -i tarama_sonucu.xml
