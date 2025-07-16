"use client"
import { useState } from "react";
import { useRouter } from 'next/navigation';
import { decodeReply } from "next/dist/server/app-render/entry-base";
import Dropzone from 'react-dropzone'


export default function Dashboard() {

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

  const handleDrop = async (acceptedFiles: File[]) => {
    const acceptedFile = acceptedFiles[0];
    let text = await acceptedFile.text();
    const buffer = await acceptedFile.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    console.log(`bytes: ${bytes}`);
    setSalt(Buffer.from(bytes.slice(0, 16)).toString('base64'));
    setNonce(Buffer.from(bytes.slice(16, 28)).toString('base64'));
    setEncryptedKey(Buffer.from(bytes.slice(28)).toString('base64'));

    setPrivateKey(await decryptPrivateKey(encryptedKey,validationPhrase,salt,nonce));

    const response = await fetch("/api/challenge", {
      method: "GET",
      headers: {
      "Content-Type": "application/json"
      }
    });

    const data = await response.json();

    let randomNonce = null;

    if(response.ok){
      randomNonce = data.nonce;
      const challengeBytes = base64ToArrayBuffer(randomNonce);
      
      const signature = await crypto.subtle.sign(
        {
          name: "RSASSA-PKCS1-v1_5"
        },
        await window.crypto.subtle.importKey(
          "pkcs8",
          base64ToArrayBuffer(privateKey),
          {
            name: "RSASSA-PKCS1-v1_5",
            hash: "SHA-256"
          },
          false,
          ["sign"]
        ),
        challengeBytes
      );

      const verifyResponse = await fetch("/signatures/verify", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          signature: Buffer.from(new Uint8Array(signature)).toString('base64'),
          challenge: randomNonce
        })
      });

      const verifyData = await verifyResponse.json();
      if (verifyResponse.ok && verifyData.success) {
        console.log("nice");
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
