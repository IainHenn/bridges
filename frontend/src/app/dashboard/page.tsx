"use client"
import { useState, useEffect } from "react";
import { useRouter } from 'next/navigation';
import { decodeReply } from "next/dist/server/app-render/entry-base";
import Dropzone from 'react-dropzone'


export default function Dashboard() {

  const router = useRouter();
  const [validated, setValidation] = useState(false);
  const [validationPhrase, setValidationPhrase] = useState("");
  const [salt, setSalt] = useState("");
  const [nonce, setNonce] = useState("");
  const [encryptedKey, setEncryptedKey] = useState("");
  const [privateKey, setPrivateKey] = useState("");

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

  function rawSigToASN1(rawSig) {
    // rawSig: ArrayBuffer or Uint8Array of length 64 (32 bytes r, 32 bytes s)
    const sig = new Uint8Array(rawSig);
    const r = sig.slice(0, 32);
    const s = sig.slice(32, 64);

  // Remove leading zeros
  function trimZeros(arr) {
    let i = 0;
    while (i < arr.length - 1 && arr[i] === 0) i++;
      return arr.slice(i);
    }
    const rTrim = trimZeros(r);
    const sTrim = trimZeros(s);

    // If high bit is set, prepend 0x00
    function prependZeroIfNeeded(arr) {
      if (arr[0] & 0x80) {
        const out = new Uint8Array(arr.length + 1);
        out[0] = 0;
        out.set(arr, 1);
        return out;
      }
      return arr;
    }
    const rEnc = prependZeroIfNeeded(rTrim);
    const sEnc = prependZeroIfNeeded(sTrim);

    // ASN.1 DER encoding
    function encodeInt(arr) {
      return [0x02, arr.length, ...arr];
    }
    const encoded = [
      0x30,
      2 + rEnc.length + 2 + sEnc.length, // total length
      ...encodeInt(rEnc),
      ...encodeInt(sEnc)
    ];
    return new Uint8Array(encoded);
  }

  function pemToArrayBuffer(pem: string): ArrayBuffer {
    const base64 = pem.replace(/-----.*-----/g, '').replace(/\s+/g, '');
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  useEffect(() => {
    fetch("http://localhost:8080/users/authorize", {
      method: "GET",
      credentials: "include"
    })
    .then(resp => {
      if(!resp.ok){
        router.push("/");
      }
    });
  }, []);

  const handleDrop = async (acceptedFiles: File[]) => {
    const acceptedFile = acceptedFiles[0];
    let text = await acceptedFile.text();
    const {salt, nonce, encryptedKey } = JSON.parse(text);
    const returnedKey = await decryptPrivateKey(encryptedKey,validationPhrase,salt,nonce);
    setPrivateKey(returnedKey);
    const response = await fetch("/api/challenge", {
      method: "GET",
      headers: {
      "Content-Type": "application/json"
      },
      credentials: "include"
    });

    const data = await response.json();

    let randomNonce = null;

    if(response.ok){
      randomNonce = data.nonce;
      const challengeBytes = base64ToArrayBuffer(randomNonce);
      const signature = await crypto.subtle.sign(
        {
          name: "ECDSA",
          hash: { name: "SHA-256" }
        },
        await window.crypto.subtle.importKey(
          "pkcs8",
          base64ToArrayBuffer(returnedKey),
          {
            name: "ECDSA",
            namedCurve: "P-256"
          },
          false,
          ["sign"]
        ),
        challengeBytes
      );


      const verifyResponse = await fetch("http://localhost:8080/signatures/verify", { 
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        credentials: "include",
        body: JSON.stringify({
          signature: Buffer.from(rawSigToASN1(signature)).toString('base64'),
          challenge: randomNonce
        })
      });

      const verifyData = await verifyResponse.json();
      if (verifyResponse.ok && verifyData.success) {
        console.log("nice");
      }
      else{
        console.log(verifyResponse.error);
      }
    }
  }
  
  return (
    <div className="flex items-center justify-center min-h-screen bg-purple-950">
      <div className="flex flex-col items-center justify-center bg-blue-500 rounded-2xl shadow-lg p-8 w-[50%] h-85 stext-black">
      {/* Drag and Drop at the top */}
      <Dropzone accept={{ 'text/plain': ['.txt'] }} onDrop={handleDrop} multiple={false}>
        {({ getRootProps, getInputProps, isDragActive }) => (
        <section>
          <div
          {...getRootProps()}
          className={`flex flex-col items-center justify-center border-2 border-dashed rounded-xl p-8 w-full transition-colors duration-200 ${
            isDragActive
            ? "border-purple-700 bg-purple-100"
            : "border-gray-300 bg-white"
          } cursor-pointer mb-6`}
          >
          <input {...getInputProps()} />
          <p className="text-lg font-semibold text-gray-700">
            {isDragActive
            ? "Drop the files here ..."
            : (
              <>
              Drag 'n drop files here <br /> or <br /> click to select
              </>
            )}
          </p>
          <p className="text-sm text-gray-500 mt-2">
            Supported format: txt
          </p>
          </div>
        </section>
        )}
      </Dropzone>
      {/* Inputs and button below */}
      <input
        id="validationPhrase"
        type="password"
        className="bg-gray-100 text-black placeholder-gray-500 hover:bg-gray-600 hover:placeholder-black rounded-md px-4 py-2 mt-2 focus:outline-none focus:ring-2 focus:ring-blue-400 transition w-full"
        placeholder="Enter your validation phrase"
        value={validationPhrase}
        onChange={e => setValidationPhrase(e.target.value)}
      />
      </div>
    </div>
  );
}
