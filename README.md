# Bridges

**Bridges** is an **end-to-end encrypted (E2EE)** data storage platform designed as a locally hosted, open-source solution for individuals seeking secure personal file and folder storage—whether on a local machine or in a private cloud setup.

## 🔐 Overview

Bridges ensures your files remain confidential and protected through multiple layers of modern cryptographic standards:

- **User Authentication**: Combines traditional username/password login with **ECDSA-based signature verification**.
- **File Encryption**: Each file is individually encrypted using **AES**.
- **Access Control**: File access rights are granted and managed using **RSA** encryption.
- **Zero-Knowledge Design**: The server has no access to unencrypted user data or private keys.

## 🧱 Stack

| Component               | Technology             |
|------------------------|------------------------|
| **Backend**            | Golang + Gin           |
| **Frontend**           | TypeScript + React.js  |
| **Relational Storage** | PostgreSQL             |
| **Metadata Storage**   | Amazon DynamoDB        |
| **Blob Storage**       | Amazon S3              |
| **Signing/Verification** | ECDSA                |
| **Encryption**         | AES (per-file), RSA    |

## 📦 Usage

1. Register and login with your username and password.
2. User will get a private key for signing and verifying requests using ECDSA (used every time after logging in).
3. User will also get a private key (RSA) for decrypting their public key (RSA) encrypted AES keys, where each AES key is linked to a file. This will be required for every download, uploads don't require the RSA private key.
4. Downloading or sharing files decrypts only with valid RSA permissions.


## 🚀 Getting Started

### Backend

```bash
go run api.go
```

###Frontend
```bash
npm run dev
```

## 🔧 Environment Variables

To run Bridges successfully, the following environment variables must be set. You can place them in a `.env` file at the root of your project.

```env
# AWS Configuration
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=
S3_BUCKET=

# PostgreSQL Configuration
DB_USER=
DB_PW=
DB_HOST=
DB_NAME=
```

## ☁️ Local vs Cloud Storage

Bridges supports both local and cloud storage configurations for encrypted files.

### 🌐 Cloud Storage

- **Encrypted files** are uploaded to an Amazon S3 bucket at:
s3://<S3_BUCKET>/user_data/<email>/<encrypted-filename>

- **File metadata** is stored in a DynamoDB table named `file_metadata` with the following schema:
- `email` (S) — partition key
- `originalFileName` (S) — sort key
- Additional fields (e.g. `fileId`, `size`, `uploadDate`, `encryptedKey`, `iv`, `mimeType`) may also be stored.

### 🖥️ Local Storage

- **Encrypted files** are saved to the local filesystem under a `user_data/` directory:
- **File metadata** can still be stored in the same DynamoDB table (`file_metadata`) using `email` and `originalFileName` as keys.


## 🧩 REST API Endpoints

All routes are prefixed under `localhost:8080`. Authenticated routes require a valid token and cookie set via `/tokens` and `/token-cookies`.

### 🔐 Authentication & Session

| Method | Endpoint             | Description                                 |
|--------|----------------------|---------------------------------------------|
| POST   | `/sessions`          | Login user and create session               |
| POST   | `/users`             | Register a new user                         |
| GET    | `/users`             | Sign out user (clears cookie and token)     |
| POST   | `/tokens`            | Generate new token                          |
| POST   | `/token-cookies`     | Set a token cookie                          |

### 🛡️ Identity Verification

| Method | Endpoint             | Description                                 |
|--------|----------------------|---------------------------------------------|
| GET    | `/api/challenge`     | Generate ECDSA challenge (signed by client) |
| POST   | `/signatures/verify` | Verify user's ECDSA signature                |
| GET    | `/users/authorize`   | Get user's public RSA key (for encryption)  |

### 📁 File Management

| Method | Endpoint                     | Description                                                                 |
|--------|------------------------------|-----------------------------------------------------------------------------|
| POST   | `/users/upload`              | Upload encrypted file to server (S3 or local)                              |
| GET    | `/users/files`               | Get list of file names for the authenticated user                          |
| POST   | `/users/files`               | Download a file by S3 path; returns base64-encoded content                 |
| DELETE | `/users/files`               | Delete specified files (metadata and blob) for authenticated user          |
| POST   | `/users/files/metadata`      | Retrieve metadata for a list of specified files (from DynamoDB)            |

> **Note**: All `/users/*` and `/api/*` routes require authentication via token and cookie.

