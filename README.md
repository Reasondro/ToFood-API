# TO Food API Documentation

## Overview
TO Food (Try Out Food) adalah layanan API berbasis AI yang digunakan untuk **menyaring dan merekomendasikan perbaikan resep makanan**. Layanan ini menggunakan **LLM (Llama 3.1 8b yang telah fine-tuned)** untuk menganalisis resep yang diberikan.

API ini dapat digunakan oleh **end-user** melalui website atau oleh **layanan pihak ketiga** melalui integrasi API.

## Links
- **Backend Service:** [TO Food API](https://tofood.codebloop.my.id/)
- **Frontend Website:** [TO Food Website](https://vermillion-moonbeam-222459.netlify.app/)
- **GitHub Backend Repo:** [ToFood API Manual](https://github.com/Reasondro/ToFood-API-Manual)
- **GitHub Frontend Repo:** [ToFood Manual Website](https://github.com/Reasondro/Tofood-Manual-Website)

## Features
- **Screening Resep:** Menentukan apakah resep makanan layak atau tidak.
- **Rekomendasi Resep:** Memberikan saran perbaikan untuk resep makanan.
- **Enkripsi Hasil Screening & Rekomendasi:** Integrasi dengan layanan enkripsi untuk keamanan data.

## API Development
API ini dikembangkan dengan melatih model LLM menggunakan **dataset buatan sendiri** yang terdiri dari tiga kolom utama:
- **Instruction**: Instruksi yang diberikan kepada model
- **Input**: Data masukan berupa resep makanan
- **Output**: Hasil analisis atau rekomendasi dari model

Fine-tuning dilakukan menggunakan **Unsloth Llama 3.1b**, yang dipilih karena dapat mempercepat proses pelatihan model dibandingkan dengan metode fine-tuning konvensional. Model ini dijalankan di VPS dengan spesifikasi yang mendukung inferensi AI berbasis LLM.


## API Authentication
TO Food API memiliki dua metode autentikasi:
1. **Token-Based Authentication** (untuk end-user/customer)
2. **API Key-Based Authentication** (untuk layanan pihak ketiga)

### 1. Generate API Key (Service Integration)
```sh
curl -X 'POST' \
  'https://tofood.codebloop.my.id/api/api-keys/generate' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{ "name": "NamaService" }'
```
**Response:**
```json
{
  "message": "API key created for NamaService",
  "id": "unique-id",
  "api_key": "your-api-key"
}
```

### 2. Register User (End-User Authentication)
```sh
curl -X 'POST' \
  'https://tofood.codebloop.my.id/api/customers/register' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{ "name": "NamaUser", "password": "UserPassword" }'
```
**Response:**
```json
{
  "id": "unique-user-id",
  "name": "NamaUser",
  "message": "Customer created successfully."
}
```

### 3. Login (Get Token)
```sh
curl -X 'POST' \
  'https://tofood.codebloop.my.id/api/customers/token' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&username=NamaUser&password=UserPassword&scope=&client_id=string&client_secret=string'
```
**Response:**
```json
{
  "access_token": "your-token",
  "token_type": "bearer"
}
```

## Core API Endpoints

### 1. Submit Recipe for Screening & Recommendation
#### a. Menggunakan API Key (Untuk layanan pihak ketiga)
```sh
curl -X 'POST' \
  'https://tofood.codebloop.my.id/api/services/prompt' \
  -H 'accept: application/json' \
  -H 'X-API-KEY: your-api-key' \
  -H 'Content-Type: application/json' \
  -d '{
    "instruction": "Resep ini layak atau tidak? Berikan rekomendasi perbaikan.",
    "input": "Resep: Rendang Daging; Bahan Utama: Daging Sapi;..."
  }'
```
**Response:**
```json
{
  "recipe_result": "Ya, resep ini layak. Tambahkan lebih banyak rempah untuk rasa yang lebih kaya."
}
```

#### b. Menggunakan Token (Untuk end-user)
```sh
curl -X 'POST' \
  'https://tofood.codebloop.my.id/api/customers/prompt' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer your-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "instruction": "Resep ini layak atau tidak? Berikan rekomendasi perbaikan.",
    "input": "Resep: Rendang Daging; Bahan Utama: Daging Sapi;..."
  }'
```
**Response:**
```json
{
  "recipe_result": "Ya, resep ini layak. Tambahkan lebih banyak rempah untuk rasa yang lebih kaya."
}
```

## Note on Performance
- Model LLM berjalan di VPS dengan spesifikasi terbatas, sehingga **respons dapat memakan waktu 10 - 20 menit**.

## Contributing
Jika ingin berkontribusi pada pengembangan TO Food API, silakan fork dan pull request di repository GitHub berikut:
- [Backend Repo](https://github.com/Reasondro/ToFood-API-Manual)
- [Frontend Repo](https://github.com/Reasondro/Tofood-Manual-Website)

## License
Lisensi dari proyek ini sesuai dengan peraturan yang ada di dalam repository GitHub.

## Contact
Untuk pertanyaan atau dukungan, silakan hubungi:
- **Alessandro Jusack Hasian** (18222025)
- Email: 18222025@std.stei.itb.ac.id
- Institut Teknologi Bandung - Sekolah Teknik Elektro dan Informatika

---
README ini dibuat berdasarkan dokumen **Tugas Besar II3160 - Teknologi Sistem Terintegrasi**.
