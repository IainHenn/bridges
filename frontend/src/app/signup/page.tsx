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
  const [encDecUrl, setEncDecUrl] = useState<string | null>(null);

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

  function arrayBufferToBase64(buffer: ArrayBuffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
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
    return arrayBufferToBase64(decrypted); 
  }

  function arrayBufferToPem(buffer: ArrayBuffer): string {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    const pem = `-----BEGIN PRIVATE KEY-----\n${base64.match(/.{1,64}/g)?.join('\n')}\n-----END PRIVATE KEY-----`;
    return pem;
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

    const keyPairEncDec = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );

    const exportedPublicKey = await crypto.subtle.exportKey("spki", keyPairEncDec.publicKey);
    const exportedPrivateKey = await crypto.subtle.exportKey("pkcs8", keyPairEncDec.privateKey);

    // 4. Convert to base64 for easier storage/transmission
    const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));
    const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPrivateKey)));

    try {
      const response = await fetch("http://localhost:8080/users", {
        method: "POST",
        body: JSON.stringify({ "email": email, 
          "password": password,
          "salt": salt,
          "nonce": nonce,
          "encryptedKey": encryptedKey,
          "publicKey": publicKey,
          "publicKeyEncDec": publicKeyBase64})
      });

      if (response.status === 201) {
        if (encryptedKey && salt && nonce) {
          const fileContent = JSON.stringify({
            salt,
            nonce,
            encryptedKey
          });
          const blob = new Blob([fileContent], { type: "application/json" });
          setUrl(URL.createObjectURL(blob));
          const blobEncDec = new Blob([JSON.stringify({privateKeyBase64})], { type: "application/json" });
          setEncDecUrl(URL.createObjectURL(blobEncDec));
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
    <div className="flex items-center justify-center min-h-screen bg-black">
      <button
        type="button"
        className="absolute left-8 top-8 bg-black border-2 border-white w-12 h-12 flex items-center justify-center p-0 hover:bg-white hover:text-black transition-colors rounded-none"
        onClick={() => router.back()}
        aria-label="Go back"
      >
        <img src="/left-arrow.svg" alt="Go back" className="invert" />
      </button>
      <div className="bg-black border-2 border-white rounded-none shadow-none p-8 w-[30%] min-w-[350px] font-mono text-white">
        <form className="flex flex-col space-y-4" onSubmit={renderSignUp}>
          <div className="flex flex-col space-y-2">
            <label htmlFor="email" className="text-white font-mono tracking-widest">
              Email
            </label>
            <input
              id="email"
              type="email"
              className="bg-black border-2 border-white text-white font-mono px-4 py-2 rounded-none placeholder-gray-400 focus:outline-none focus:border-white focus:bg-black transition-colors"
              placeholder="Enter your email"
              autoComplete="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              style={{ letterSpacing: "1px" }}
            />
          </div>
          <div className="flex flex-col space-y-2">
            <label htmlFor="password" className="text-white font-mono tracking-widest">
              Password
            </label>
            <input
              id="password"
              type="password"
              className="bg-black border-2 border-white text-white font-mono px-4 py-2 rounded-none placeholder-gray-400 focus:outline-none focus:border-white focus:bg-black transition-colors"
              placeholder="Enter your password"
              autoComplete="current-password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              style={{ letterSpacing: "1px" }}
            />
            <input
              id="validationPhrase"
              type="password"
              className="bg-black border-2 border-white text-white font-mono px-4 py-2 rounded-none placeholder-gray-400 focus:outline-none focus:border-white focus:bg-black transition-colors"
              placeholder="Enter your validation phrase"
              autoComplete="current-validation-phrase"
              value={validationPhrase}
              onChange={e => setValidationPhrase(e.target.value)}
              style={{ letterSpacing: "1px" }}
            />
          </div>
          <button
            type="submit"
            className="bg-black border-2 border-white text-white font-mono font-bold py-2 rounded-none transition-colors w-full mt-2 hover:bg-white hover:text-black"
            style={{ letterSpacing: "2px" }}
          >
            Sign Up
          </button>
          {url && (
            <a
              href={url}
              download="privateKey.txt"
              className="bg-black border-2 border-green-500 text-green-400 font-mono font-bold py-2 rounded-none transition-colors w-full mt-2 flex justify-center items-center hover:bg-green-500 hover:text-black"
              style={{ letterSpacing: "1px" }}
            >
              Download Private Key (Can't login without it!)
            </a>
          )}
          {encDecUrl && (
            <a
              href={encDecUrl}
              download="privateKey_enc_dec.txt"
              className="bg-black border-2 border-green-500 text-green-400 font-mono font-bold py-2 rounded-none transition-colors w-full mt-2 flex justify-center items-center hover:bg-green-500 hover:text-black"
              style={{ letterSpacing: "1px" }}
            >
              Download Private Key (Can't download files without it!)
            </a>
          )}
        </form>
      </div>
    </div>
  );
}
