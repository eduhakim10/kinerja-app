# Aplikasi Manajemen Kinerja

Aplikasi Manajemen Kinerja adalah aplikasi berbasis web yang memungkinkan pengguna untuk mengelola laporan, tugas, dan pengguna. Aplikasi ini mendukung fitur CRUD (Create, Read, Update, Delete) untuk pengguna dan laporan, serta manajemen tugas.

## Fitur

- **Manajemen Pengguna**: Tambah, lihat, perbarui, dan hapus pengguna.
- **Manajemen Laporan**: Buat dan lihat laporan dengan status verifikasi.
- **Manajemen Tugas**: Buat dan kelola tugas yang ditugaskan kepada pengguna.
- **Autentikasi**: Pengguna dapat login untuk mengakses fitur aplikasi.

## Teknologi yang Digunakan

- **Bahasa Pemrograman**: Go
- **Framework**: [httprouter](https://github.com/julienschmidt/httprouter)
- **Database**: MySQL
- **Template**: HTML
- **CSS**: Bootstrap (opsional)

## Instalasi

1. **Clone Repository**:
   ```bash
git clone https://github.com/eduhakim10/kinerja-app.git
 

2. Buat database baru dengan nama kinerja_db kemudian execute query sesuai pada file db.sql pada (root directory)
3. Ubah username dan password Database Mysql cmd/server/main.go line 23 kemudian Run aplikasi
      ```bash
   cd kinerja-app
   go run cmd/server/main.go

4. Create New User untuk login
   End point http://localhost:8000/users
   Postman tab body pilih Raw dengan method POST
      ```bash
   {
    "name" : "Alice Junior",
    "username": "alice",
    "password": "password123",
    "role": "Admin"
   }
5. Akses http://localhost:8000 maka akan tampil form login menggunakan username dan password
