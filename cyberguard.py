
import os
import re
import ssl
import json
import time
import socket
import ipaddress
import requests

from urllib.parse import urlparse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

# =========================================
# CYBER WEBGUARD SCANNER
# =========================================

G = "\033[92m"
C = "\033[96m"
Y = "\033[93m"
R = "\033[91m"
M = "\033[95m"
W = "\033[97m"
D = "\033[90m"
B = "\033[1m"
X = "\033[0m"

FILE_RIWAYAT = "webguard_history.json"
TIMEOUT = 10


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def loading(teks):
    print(f"\n{C}[*] {teks}{X}")

    for i in range(21):
        bar = "#" * i + "-" * (20 - i)
        print(
            f"\r{G}[{bar}] {i * 5:3d}%{X}",
            end="",
            flush=True
        )
        time.sleep(0.025)

    print(f"\n{G}[OK] Pemeriksaan selesai.{X}")


def banner():
    print(f"""{G}{B}
   ██████╗██╗   ██╗██████╗ ███████╗██████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
{X}{C}
            CYBER WEBGUARD SCANNER
{M}              WEB SECURITY PRO{X}
{G}{B}              CREATED MOH.BAYU
{D}=================================================={X}
""")


def simpan_riwayat(data):
    riwayat = baca_riwayat()
    riwayat.append(data)

    try:
        with open(FILE_RIWAYAT, "w", encoding="utf-8") as f:
            json.dump(
                riwayat, f, indent=4, ensure_ascii=False
            )
        print(f"{G}[+] Laporan tersimpan.{X}")

    except OSError as e:
        print(f"{R}[!] Gagal menyimpan: {e}{X}")


def baca_riwayat():
    if not os.path.exists(FILE_RIWAYAT):
        return []

    try:
        with open(FILE_RIWAYAT, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []

    except (OSError, json.JSONDecodeError):
        print(f"{R}[!] File riwayat tidak dapat dibaca.{X}")
        return []


def validasi_target(url):
    url = url.strip()

    if not url.startswith(("https://", "http://")):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Hanya HTTP dan HTTPS yang didukung.")

    if not parsed.hostname:
        raise ValueError("Alamat website tidak valid.")

    if parsed.username or parsed.password:
        raise ValueError("URL dengan kredensial tidak diperbolehkan.")

    if parsed.port not in (None, 80, 443):
        raise ValueError("Port khusus tidak didukung.")

    hostname = parsed.hostname

    # Cegah target localhost atau alamat jaringan privat.
    try:
        alamat = ipaddress.ip_address(hostname)

        if not alamat.is_global:
            raise ValueError("Alamat IP harus merupakan IP publik.")

    except ValueError as e:
        if "IP harus" in str(e):
            raise

        try:
            hasil_dns = socket.getaddrinfo(
                hostname, None, type=socket.SOCK_STREAM
            )

            if not hasil_dns:
                raise ValueError("Domain tidak ditemukan.")

            for hasil in hasil_dns:
                ip = ipaddress.ip_address(hasil[4][0])
                if not ip.is_global:
                    raise ValueError(
                        "Domain mengarah ke alamat nonpublik."
                    )

        except socket.gaierror:
            raise ValueError("Domain tidak dapat ditemukan.")

    return url


def cek_header(headers):
    pemeriksaan = {
        "Content-Security-Policy": (
            "Mengatur sumber konten yang diizinkan"
        ),
        "Strict-Transport-Security": (
            "Membantu memaksa koneksi HTTPS"
        ),
        "X-Content-Type-Options": (
            "Mengurangi risiko MIME sniffing"
        ),
        "X-Frame-Options": (
            "Perlindungan framing untuk browser"
        ),
        "Referrer-Policy": (
            "Mengatur informasi referrer"
        ),
        "Permissions-Policy": (
            "Mengatur fitur browser"
        )
    }

    temuan = []
    jumlah_hilang = 0

    print(f"\n{C}=== SECURITY HEADERS ==={X}")

    for nama, fungsi in pemeriksaan.items():
        nilai = headers.get(nama)

        if nilai:
            status = f"{G}ADA{X}"
        else:
            status = f"{Y}TIDAK ADA{X}"
            jumlah_hilang += 1

        print(f"{status} {nama}")
        temuan.append({
            "header": nama,
            "status": "ada" if nilai else "tidak ada",
            "fungsi": fungsi
        })

    return temuan, jumlah_hilang


def cek_tls(host):
    print(f"\n{C}=== HTTPS / TLS ==={X}")

    try:
        konteks = ssl.create_default_context()

        with socket.create_connection(
            (host, 443), timeout=TIMEOUT
        ) as sock:
            with konteks.wrap_socket(
                sock, server_hostname=host
            ) as tls:
                sertifikat = tls.getpeercert()

        kedaluwarsa = datetime.strptime(
            sertifikat["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        sekarang = datetime.now(timezone.utc)
        sisa_hari = (kedaluwarsa - sekarang).days

        print(f"{G}[+] Sertifikat valid saat diperiksa.{X}")
        print(f"{C}Tanggal kedaluwarsa: {kedaluwarsa}{X}")
        print(f"{C}Sisa hari: {sisa_hari}{X}")

        return {
            "berhasil": True,
            "kedaluwarsa": kedaluwarsa.isoformat(),
            "sisa_hari": sisa_hari
        }

    except (OSError, ssl.SSLError, KeyError, ValueError) as e:
        print(f"{R}[!] TLS gagal diverifikasi: {e}{X}")

        return {
            "berhasil": False,
            "error": str(e)
        }


def pindai_website():
    print(f"\n{C}=== WEB SECURITY SCAN ==={X}")
    masukan = input("Masukkan domain atau URL: ").strip()

    try:
        url = validasi_target(masukan)
    except ValueError as e:
        print(f"{R}[!] {e}{X}")
        return

    loading("Memeriksa koneksi website")

    hasil = {
        "waktu": datetime.now().isoformat(timespec="seconds"),
        "url_awal": url,
        "status_http": None,
        "url_akhir": None,
        "https": url.startswith("https://"),
        "headers": [],
        "tls": None,
        "indikasi": [],
        "risiko": "Belum dinilai"
    }

    try:
        # GET biasa dengan batas waktu, tanpa mengirim payload uji.
        with requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=True,
            stream=True,
            headers={"User-Agent": "CyberWebGuard/1.0"}
        ) as response:
            hasil["status_http"] = response.status_code
            hasil["url_akhir"] = response.url
            headers = response.headers.copy()

        print(f"\n{C}=== HASIL KONEKSI ==={X}")
        print(f"URL akhir : {hasil['url_akhir']}")
        print(f"HTTP      : {hasil['status_http']}")
        print(
            "HTTPS     :",
            "Ya" if hasil["url_akhir"].startswith("https://")
            else "Tidak"
        )

        if 200 <= hasil["status_http"] < 400:
            print(f"{G}[+] Website merespons.{X}")
        else:
            print(f"{Y}[!] Respons perlu diperiksa.{X}")

        # Periksa header URL akhir.
        hasil["headers"], hilang = cek_header(headers)

        if hilang:
            hasil["indikasi"].append(
                f"{hilang} header keamanan tidak ditemukan"
            )

        if not hasil["url_akhir"].startswith("https://"):
            hasil["indikasi"].append("URL akhir tidak menggunakan HTTPS")
            hasil["tls"] = {
                "berhasil": False,
                "error": "URL akhir tidak menggunakan HTTPS"
            }
        else:
            host = urlparse(hasil["url_akhir"]).hostname
            hasil["tls"] = cek_tls(host)

            if not hasil["tls"]["berhasil"]:
                hasil["indikasi"].append(
                    "Sertifikat TLS tidak berhasil diverifikasi"
                )
            elif hasil["tls"]["sisa_hari"] < 0:
                hasil["indikasi"].append("Sertifikat TLS kedaluwarsa")
            elif hasil["tls"]["sisa_hari"] < 30:
                hasil["indikasi"].append(
                    "Sertifikat TLS akan kedaluwarsa dalam 30 hari"
                )

        # Skor heuristik sederhana, bukan audit penuh.
        skor = 100

        if not hasil["url_akhir"].startswith("https://"):
            skor -= 35

        if not hasil["tls"]["berhasil"]:
            skor -= 30

        skor -= min(hilang * 5, 30)

        if hasil["status_http"] >= 400:
            skor -= 10

        skor = max(0, skor)

        if skor >= 80:
            risiko = "Indikasi risiko rendah"
            warna = G
        elif skor >= 50:
            risiko = "Indikasi risiko sedang"
            warna = Y
        else:
            risiko = "Indikasi risiko tinggi"
            warna = R

        hasil["skor_indikatif"] = skor
        hasil["risiko"] = risiko

        print(f"\n{C}=== RINGKASAN ==={X}")
        print(f"Skor indikatif : {warna}{skor}/100{X}")
        print(f"Kategori       : {warna}{risiko}{X}")

        if hasil["indikasi"]:
            for item in hasil["indikasi"]:
                print(f"{Y}[!] {item}{X}")
        else:
            print(f"{G}[+] Tidak ditemukan indikator dari pemeriksaan dasar.{X}")

        print(
            f"\n{D}Skor ini hanya heuristik header dan TLS; "
            f"bukan bukti website aman atau bebas malware.{X}"
        )

        simpan_riwayat(hasil)

    except requests.RequestException as e:
        print(f"\n{R}[!] Website gagal diperiksa: {e}{X}")


def lihat_riwayat():
    data = baca_riwayat()

    print(f"\n{C}=== RIWAYAT WEB SCAN ==={X}")

    if not data:
        print(f"{Y}Belum ada riwayat scan.{X}")
        return

    for i, item in enumerate(data, 1):
        print(f"\n{G}[{i}] {item.get('url_awal', '-')}{X}")
        print("Waktu :", item.get("waktu", "-"))
        print("HTTP  :", item.get("status_http", "-"))
        print("Risiko:", item.get("risiko", "-"))
        print("Skor  :", item.get("skor_indikatif", "-"))


def hapus_riwayat():
    data = baca_riwayat()

    if not data:
        print(f"{Y}Riwayat kosong.{X}")
        return

    lihat_riwayat()

    print(f"\n{Y}[1]{W} Hapus satu laporan")
    print(f"{R}[2]{W} Hapus semua laporan")
    print(f"{D}[0]{W} Batal")

    pilihan = input("Pilih: ").strip()

    if pilihan == "1":
        try:
            nomor = int(input("Nomor laporan: "))

            if not 1 <= nomor <= len(data):
                print(f"{R}Nomor tidak ditemukan.{X}")
                return

            if input("Ketik HAPUS untuk konfirmasi: ") == "HAPUS":
                data.pop(nomor - 1)

                with open(FILE_RIWAYAT, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)

                print(f"{G}Laporan dihapus.{X}")
            else:
                print("Dibatalkan.")

        except ValueError:
            print("Nomor harus berupa angka.")

    elif pilihan == "2":
        if input("Ketik HAPUS SEMUA untuk konfirmasi: ") == "HAPUS SEMUA":
            with open(FILE_RIWAYAT, "w", encoding="utf-8") as f:
                json.dump([], f, indent=4)

            print(f"{G}Semua laporan dihapus.{X}")
        else:
            print("Dibatalkan.")

    elif pilihan == "0":
        print("Dibatalkan.")


def menu():
    while True:
        clear()
        banner()

        print(f"""{C}
╔════════════════ MAIN MENU ════════════════╗
{G} [01] {W}Scan Keamanan Website
{C} [02] {W}Lihat Riwayat Scan
{R} [03] {W}Hapus Riwayat
{Y} [04] {W}Tentang Scanner
{D} [00] {W}Keluar
{C}╚══════════════════════════════════════════╝{X}
""")

        pilih = input(f"{G}root@cyber-webguard:~$ {X}").strip()

        if pilih in ("1", "01"):
            pindai_website()
            input("\nTekan Enter untuk kembali...")

        elif pilih in ("2", "02"):
            lihat_riwayat()
            input("\nTekan Enter untuk kembali...")

        elif pilih in ("3", "03"):
            hapus_riwayat()
            input("\nTekan Enter untuk kembali...")

        elif pilih in ("4", "04"):
            print(f"""
{C}CYBER WEBGUARD SCANNER{X}
Pemeriksaan pasif:
- Status HTTP dan redirect
- Header keamanan
- Sertifikat TLS
- Riwayat laporan JSON

Tidak melakukan eksploitasi atau uji penetrasi.
Gunakan hanya pada website yang kamu miliki
atau yang kamu punya izin untuk periksa.
""")
            input("Tekan Enter untuk kembali...")

        elif pilih in ("0", "00"):
            print(f"{M}Menutup Cyber WebGuard...{X}")
            break

        else:
            print(f"{R}[!] Menu tidak tersedia.{X}")
            time.sleep(1)


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print(f"\n{Y}Program dihentikan.{X}")
