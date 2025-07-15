"use client"
import { useState } from "react";
import { useRouter } from 'next/navigation';
import { decodeReply } from "next/dist/server/app-render/entry-base";


export default function SignUp() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [validationPhrase, setValidationPhrase] = useState("");

  const router = useRouter();
  const [url, setUrl] = useState<string | null>(null);

  // Helper to convert base64 to ArrayBuffer
  function base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // Decrypt private key using password, salt, and nonce
  async function decryptPrivateKey(
    encryptedBlobBase64: string,
    password: string,
    saltBase64: string,
    nonceBase64: string
  ): Promise<string> {
    const encryptedBlob = base64ToArrayBuffer(encryptedBlobBase64);
    const salt = base64ToArrayBuffer(saltBase64);
    const nonce = base64ToArrayBuffer(nonceBase64);

    // Derive key with PBKDF2
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2", false, ["deriveKey"]
    );

    const key = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    // Decrypt private key bytes
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce
      },
      key,
      encryptedBlob
    );
    return new TextDecoder().decode(decrypted); 
  }

  const renderSignUp = async (event: React.FormEvent) => {
    event.preventDefault();
    const encoder = new TextEncoder();
    const saltBytes = window.crypto.getRandomValues(new Uint8Array(16));
    const nonceBytes = window.crypto.getRandomValues(new Uint8Array(12));

    // Generate an asymmetric key pair (ECDSA)
    const keyPair = await window.crypto.subtle.generateKey(
      {
      name: "ECDSA",
      namedCurve: "P-256"
      },
      true,
      ["sign", "verify"]
    );

    // Export public key as spki (base64)
    const publicKeyBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    function arrayBufferToBase64(buffer: ArrayBuffer) {
      const bytes = new Uint8Array(buffer);
      let binary = "";
      for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
      }
      return window.btoa(binary);
    }
    const publicKey = arrayBufferToBase64(publicKeyBuffer);

    // Export private key as pkcs8 (base64)
    const privateKeyBuffer = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    // Derive encryption key from validationPhrase
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      encoder.encode(validationPhrase),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    const key = await window.crypto.subtle.deriveKey(
      {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 100000,
      hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );

    // Encrypt the private key using AES-GCM
    const encryptedKeyBuffer = await window.crypto.subtle.encrypt(
      {
      name: "AES-GCM",
      iv: nonceBytes
      },
      key,
      privateKeyBuffer
    );

    const salt = arrayBufferToBase64(saltBytes.buffer);
    const nonce = arrayBufferToBase64(nonceBytes.buffer);
    const encryptedKey = arrayBufferToBase64(encryptedKeyBuffer);
    try {
      const response = await fetch("http://localhost:8080/users", {
        method: "POST",
        body: JSON.stringify({ "email": email, 
          "password": password,
          "salt": salt,
          "nonce": nonce,
          "encryptedKey": encryptedKey,
          "publicKey": publicKey})
      });

      if (response.status === 201) {
        console.log("user created");

        if (encryptedKey && salt && nonce) {
          const privateKey = await decryptPrivateKey(encryptedKey, validationPhrase, salt, nonce);
          const blob = new Blob([privateKey], { type: "text/plain" });
          setUrl(URL.createObjectURL(blob));
        }
      } else {
        console.log(`Failed to create user: ${response.status}`);
      }
    } catch (error) {
      console.error("Error:", error);
    }
  };
  const sss = () => {
    router.push('/signup');
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-purple-950">
      <button
        type="button"
        className="absolute left-8 top-8 bg-white w-[3%] h-[6%] font-bold text-purple-700 rounded p-2 hover:bg-gray-200 transition"
        onClick={() => router.back()}
        aria-label="Go back"
      >
        <img src="/left-arrow.svg" alt="Go back" />
      </button>
      <div className="bg-blue-500 rounded-2xl shadow-lg p-8 w-[30%] h-85 text-black">
        <div className="flex flex-col space-y-2">
          <label htmlFor="email" className="text-white font-semibold">
          Email
          </label>
          <input
          id="email"
          type="email"
          className="bg-gray-100 text-black placeholder-gray-500 hover:bg-gray-600 hover:placeholder-black rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400 transition"
          placeholder="Enter your email"
          autoComplete="email"
          value={email}
          onChange={e => setEmail(e.target.value)}
          />
        </div>
        <div className="flex flex-col space-y-2">
          <label htmlFor="password" className="text-white font-semibold">
            Password
          </label>
          <input
            id="password"
            type="password"
            className="bg-gray-100 text-black placeholder-gray-500 hover:bg-gray-600 hover:placeholder-black rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400 transition"
            placeholder="Enter your password"
            autoComplete="current-password"
            value={password}
            onChange={e => setPassword(e.target.value)}
          />
          <input
            id="validationPhrase"
            type="password"
            className="bg-gray-100 text-black placeholder-gray-500 hover:bg-gray-600 hover:placeholder-black rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400 transition"
            placeholder="Enter your validation phrase"
            autoComplete="current-validation-phrase"
            value={validationPhrase}
            onChange={e => setValidationPhrase(e.target.value)}
          />
        </div>
        <button
          onClick={renderSignUp}
          className="bg-purple-700 hover:bg-purple-800 text-white font-bold py-2 rounded-md transition w-full mt-4"
        >
        Sign Up
        </button>
        {url && (
          <a
          href={url}
          download="privateKey.txt"
          className="bg-green-600 hover:bg-green-700 text-white font-bold py-2 rounded-md transition w-full mt-4 flex justify-center items-center"
          >
          Download Private Key
          </a>
        )}
      </div>
    </div>
  );
}
