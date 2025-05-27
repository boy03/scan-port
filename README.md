# JCS-BOY - Jogja Cyber Security

BOY (Basic Offensive Utility) adalah sebuah tool pentesting sederhana berbasis Python yang memiliki fitur port scanning, brute force (SSH), dan pendeteksi celah keamanan.

## 🚀 Fitur

- 🔍 **Port Scanner**: Deteksi port terbuka dalam rentang tertentu.
- 🔑 **Brute Force SSH**: Serangan brute force terhadap layanan SSH dengan file username dan password.
- 🛡️ **Vulnerability Scanner**: Mendeteksi kerentanan yang diketahui pada target.

## 📦 Instalasi

Pastikan Anda memiliki Python 3.x terinstal. Clone repository dan jalankan tool:

```bash``` <br>
git clone (repository-url) <br>
cd (nama-folder) python3 boy.py 

```Scan port```
python3 boy.py 192.168.1.10 20-80 scan

```Brute force SSH```
python3 boy.py 192.168.1.10 22 brute_force_ssh userlist.txt passlist.txt

```Cek kerentanan```
python3 boy.py 192.168.1.10 - check_vulnerabilities

# ⚠️ Disclaimer
Tool ini hanya digunakan untuk tujuan edukasi dan pengujian keamanan pada sistem yang Anda miliki atau Anda miliki izin eksplisit untuk menguji. Penulis tidak bertanggung jawab atas penyalahgunaan.

# 📸 Foto
![image](https://github.com/user-attachments/assets/e4181622-516a-43e9-abad-47fc1942810a)

