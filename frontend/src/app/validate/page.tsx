"use client"
import { useState, useEffect } from "react";
import { useRouter } from 'next/navigation';
import { decodeReply } from "next/dist/server/app-render/entry-base";
import Dropzone from 'react-dropzone'


export default function Validation() {

  const router = useRouter();
  const [validationPhrase, setValidationPhrase] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [fileText, setFileText] = useState("");

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
    setFileText(text);
  }

  function signOut() {
    fetch("http://localhost:8080/users", {
      method: "GET",
      credentials: "include"
    })
    .then(resp => {
      if(resp.ok){
        router.push("/");
      }
    })
  }

  async function submitInfo() {
    const {salt, nonce, encryptedKey } = JSON.parse(fileText);
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
        router.push("/files");
      }
      else{
        console.log(verifyResponse.error);
      }
    }
  }
  
  return (
    <div className="flex items-center justify-center min-h-screen bg-black">
      <div className="flex flex-col items-center justify-center bg-black border-2 border-white rounded-none shadow-none p-8 w-[40%] min-w-[350px] font-mono text-white">
        <Dropzone accept={{ "text/plain": [".txt"] }} onDrop={handleDrop} multiple={false}>
          {({ getRootProps, getInputProps, isDragActive }) => (
            <section>
              <div
                {...getRootProps()}
                className={`flex flex-col items-center justify-center border-2 border-dashed rounded-none p-8 w-full transition-colors duration-200 font-mono ${
                  isDragActive
                    ? "bg-white border-black text-black"
                    : "bg-black border-white text-white"
                } cursor-pointer mb-6`}
                style={{ letterSpacing: "1px" }}
              >
                <input {...getInputProps()} />
                <p className="text-lg font-mono">
                  {isDragActive
                    ? "Drop your privateKey.txt here..."
                    : (
                      <>
                        Drag & drop your privateKey.txt here<br />or click to select
                      </>
                    )}
                </p>
                <p className="text-sm mt-2 font-mono">
                  Supported format: txt
                </p>
              </div>
            </section>
          )}
        </Dropzone>
        <input
          id="validationPhrase"
          type="password"
          className="bg-black border-2 border-white text-white font-mono px-4 py-2 mt-2 rounded-none placeholder-gray-400 focus:outline-none focus:border-white focus:bg-black transition-colors w-full"
          placeholder="Enter your validation phrase"
          value={validationPhrase}
          onChange={e => setValidationPhrase(e.target.value)}
          style={{ letterSpacing: "1px" }}
        />
        <button
            className="bg-black border-2 border-white text-white font-mono font-bold py-2 rounded-none transition-colors w-full mt-2 hover:bg-white hover:text-black"
            style={{ letterSpacing: "2px" }}
            onClick={submitInfo}
          >
        Validate Information
        </button>
        <button
            className="bg-black border-2 border-white text-white font-mono font-bold py-2 rounded-none transition-colors w-full mt-2 hover:bg-white hover:text-black"
            style={{ letterSpacing: "2px" }}
            onClick={signOut}
          >
        Sign Out
        </button>
      </div>
    </div>
  );
}
