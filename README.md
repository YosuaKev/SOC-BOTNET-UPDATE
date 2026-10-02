# Zeek Botnet + Behavior Installer v1.3.2-XFF

Update ini dibuat di atas installer v1.3.1 dan menambahkan dukungan **original client/source IP** dari Zeek `http.log` field `proxied`, khususnya:

```json
"id.orig_h": "10.70.184.2",
"proxied": ["X-FORWARDED-FOR -> 149.102.243.44"]
```

Untuk kondisi tersebut detector akan menghasilkan alert HTTP seperti:

```json
{
  "src_ip": "149.102.243.44",
  "original_src_ip": "149.102.243.44",
  "observed_src_ip": "10.70.184.2",
  "zeek_src_ip": "10.70.184.2",
  "proxy_ip": "10.70.184.2",
  "source_ip_source": "x_forwarded_for"
}
```

Dengan demikian website yang sudah menampilkan field `src_ip` akan mendapatkan IP client sebelum WAF/firewall untuk **HTTP_BRUTE_FORCE**, sementara IP yang benar-benar dilihat Zeek tetap tersimpan di `observed_src_ip`.

## Keamanan X-Forwarded-For

XFF hanya dipercaya jika `id.orig_h` adalah proxy/WAF tepercaya. Default paket ini adalah:

```text
10.70.184.2
```

Jika ada proxy lain, gunakan `--trusted-proxy IP` berulang kali atau environment `TRUSTED_PROXIES`.

## Yang tidak berubah dari v1.3.1

- Random Forest/model dan threshold tetap.
- `zeek-botnet-detector.service` tidak diubah.
- Dedicated Filebeat tetap terpisah dari `/etc/filebeat/filebeat.yml` dan service Filebeat utama.
- Elasticsearch tujuan tidak diubah.
- Ignore service yang sudah dipakai service tetap didukung.
- Mode detector tetap shadow; tidak melakukan blocking.

## Penting: cakupan original source IP

`X-Forwarded-For` adalah metadata HTTP. Karena itu source IP sebelum firewall dapat dipulihkan dengan metode ini pada alert yang berasal dari `http.log`, terutama `HTTP_BRUTE_FORCE`.

Untuk `SSH_BRUTE_FORCE`, `PORT_SCAN`, `HOST_SCAN`, `CONNECTION_FLOOD`, dan `BEACONING` yang berasal dari `conn.log`, detector tetap memakai `id.orig_h`. XFF memang tidak tersedia pada trafik non-HTTP tersebut.

## A. Update VM yang sudah memakai v1.3.1

Extract ZIP, lalu:

```bash
cd zeek-botnet-installer-v1.3.2-xff
sudo ./apply-xff-update.sh \
  --repo /home/raka/SOC-BOTNET \
  --trusted-proxy 10.70.184.2
```

Script akan:

1. backup `behavior_detector.py` lama;
2. memasang versi XFF-aware ke `/opt/zeek-botnet-detector/src/behavior_detector.py`;
3. memperbarui copy `src/behavior_detector.py` pada repo bila `--repo` diberikan;
4. membuat systemd drop-in `TRUSTED_PROXIES`;
5. restart hanya `zeek-behavior-detector.service`.

Verifikasi:

```bash
sudo ./verify-xff.sh
```

## B. Fresh install menggunakan installer v1.3.1 yang sudah ada di SOC-BOTNET

Repo base tetap memuat model RF dan seluruh file installer v1.3.1. Gunakan wrapper ini agar base installer dijalankan lebih dahulu dan update XFF diterapkan otomatis:

```bash
sudo ./install-v1.3.2.sh \
  --repo /home/raka/SOC-BOTNET \
  --interface ens160 \
  --trusted-proxy 10.70.184.2
```

Jika Zeek sudah terpasang:

```bash
sudo ./install-v1.3.2.sh \
  --repo /home/raka/SOC-BOTNET \
  --interface ens160 \
  --skip-zeek-install \
  --trusted-proxy 10.70.184.2
```

## C. Push perubahan ke GitHub SOC-BOTNET

Setelah menjalankan update dengan `--repo /home/raka/SOC-BOTNET`, file berikut pada repo sudah diganti:

```text
/home/raka/SOC-BOTNET/src/behavior_detector.py
```

Kemudian dari repo:

```bash
cd /home/raka/SOC-BOTNET
git status
git add src/behavior_detector.py
git commit -m "add trusted X-Forwarded-For original source IP"
git push origin main
```

Setelah file baru ada di repository, base installer yang menyalin `src/behavior_detector.py` akan memakai versi baru. Versi ini juga memiliki fallback trusted proxy `10.70.184.2`, sehingga tetap kompatibel dengan unit lama yang belum memiliki flag XFF.

## Verifikasi manual data XFF dari Zeek

```bash
sudo tail -F /opt/zeek/logs/current/http.log | jq 'select(.proxied != null) | {
  observed_ip: ."id.orig_h",
  proxied: .proxied,
  host: .host,
  uri: .uri
}'
```

Untuk AlmaLinux/package Zeek, path `http.log` dapat berbeda. `verify-xff.sh` juga mencari beberapa path umum secara otomatis.

## Field untuk dashboard

Gunakan:

```text
src_ip              -> alamat source utama untuk ditampilkan
original_src_ip     -> client IP hasil trusted XFF, bila tersedia
observed_src_ip     -> alamat source yang benar-benar terlihat Zeek
source_ip_source    -> x_forwarded_for atau zeek_id.orig_h
```

Jadi pada dashboard:

```text
Source IP          149.102.243.44
Observed via Proxy 10.70.184.2
```

Filebeat akan mengirim field JSON baru tersebut bersama alert behavior seperti field lainnya.
