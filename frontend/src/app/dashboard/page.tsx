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
    console.log("encryptedBlobBase64:", encryptedBlobBase64);
    console.log("saltBase64:", saltBase64);
    console.log("nonceBase64:", nonceBase64);

    const encryptedBlob = base64ToArrayBuffer(encryptedBlobBase64);
    const salt = base64ToArrayBuffer(saltBase64);
    const nonce = base64ToArrayBuffer(nonceBase64);

    console.log("encryptedBlobBuffer:", encryptedBlob);
    console.log("saltBuffer:", salt);
    console.log("nonceBuffer:", nonce);

    console.log("inside decryptPrivateKey");
    // Derive key with PBKDF2
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2", false, ["deriveKey"]
    );
    console.log("after keyMaterial");
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
    console.log("after key creation");

    // Decrypt private key bytes
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce
      },
      key,
      encryptedBlob
    );
    console.log("after decrypted");
    return arrayBufferToBase64(decrypted); 
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

  const handleDrop = async (acceptedFiles: File[]) => {
    const acceptedFile = acceptedFiles[0];
    let text = await acceptedFile.text();
    const {salt, nonce, encryptedKey } = JSON.parse(text);
    console.log("salt:", salt);
    console.log("nonce:", nonce);
    console.log("encryptedKey:", encryptedKey);
    console.log("raw pem: ", text);
    const returnedKey = await decryptPrivateKey(encryptedKey,validationPhrase,salt,nonce);
    setPrivateKey(returnedKey);
    const response = await fetch("http://localhost:8080/api/challenge", {
      method: "GET",
      headers: {
      "Content-Type": "application/json"
      }
    });

    const data = await response.json();

    let randomNonce = null;

    console.log("here");
    if(response.ok){
      console.log("in here");
      randomNonce = data.nonce;
      console.log("random nonce: ", randomNonce);
      const challengeBytes = base64ToArrayBuffer(randomNonce);
      console.log("returned key: ", returnedKey);
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

      console.log("right before verifyResponse");

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
