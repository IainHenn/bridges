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
