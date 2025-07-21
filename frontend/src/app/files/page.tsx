"use client"
import { useState, useEffect } from "react";
import { useRouter } from 'next/navigation';
import { decodeReply } from "next/dist/server/app-render/entry-base";
import Dropzone from 'react-dropzone'


export default function files() {

  type FilePreview = {
    FileName: string
    LastModified: string
  }
  
  const router = useRouter();
  const [files, setFiles] = useState<FilePreview[]>([]);
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const [selectAll, setSelectAll] = useState(false);
  type FileMetadata = {
    fullPath: string;
    uploadDate: Date;
    lastModified: number;
    name: string;
    webkitRelativePath: string;
    size: number;
    type: string;
    arrayBuffer: () => Promise<ArrayBuffer>;
    bytes: () => Promise<Uint8Array>;
    slice: (start?: number, end?: number, contentType?: string) => Blob;
    stream: () => ReadableStream<Uint8Array>;
    text: () => Promise<string>;
    iv?: string;
    encryptedAesKey?: string;
    encryptedFile?: string;
    fileType?: string;
  };

  const downloadFiles = () => {
    console.log(selectedFiles);
    fetch("http://localhost:8080/users/files", {
        method: "POST", 
        credentials: "include", 
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            selectedFiles
        })
    })
    .then(resp => resp.json())
    .then(data => {
        console.log(data);
        data.files.forEach( async (file: any) => {
            const { encryptedfile, iv, encryptedAesKey, fileType, FileName } = file;

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

            // Get user's private RSA key from sessionStorage (assume it's stored as base64 PKCS8)
            const publicKeyBase64 = sessionStorage.getItem("aes_public_key");
            if (!publicKeyBase64) {
                alert("No public key found in sessionStorage.");
                return;
            }
            console.log("A");
            const privateKey = await window.crypto.subtle.importKey(
                "spki",
                base64ToArrayBuffer(publicKeyBase64),
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                false,
                ["decrypt"]
            );
            console.log("B");
            // Decrypt AES key with RSA private key
            const aesKeyRaw = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                privateKey,
                base64ToArrayBuffer(encryptedAesKey)
            );
            console.log("C");
            // Import decrypted AES key
            const aesKey = await window.crypto.subtle.importKey(
                "raw",
                aesKeyRaw,
                { name: "AES-GCM" },
                false,
                ["decrypt"]
            );
            console.log("D");
            // Decrypt file data with AES key
            const decryptedContent = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: base64ToArrayBuffer(iv)
                },
                aesKey,
                base64ToArrayBuffer(encryptedfile)
            );
            console.log("E");
            // Download the decrypted file
            const blob = new Blob([decryptedContent], { type: fileType || "application/octet-stream" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = FileName || "downloaded_file";
            document.body.appendChild(a);
            a.click();
            setTimeout(() => {
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }, 100);
        });
    });
  }

  const selectAllFiles = () => {

    if(selectAll == false){
        setSelectedFiles(files.map(f => f.FileName));
        setSelectAll(true);
    }
    else {
    setSelectedFiles([]);
    setSelectAll(false);
    }
  }

  useEffect(() => {
    fetch("http://localhost:8080/users/authorize", {
        method: "GET",
        credentials: "include",
        headers: {
            "Content-Type": "application/json"
        }
    })
    .then(resp => {
        if(!resp.ok){
            router.push("/")
        } else {
            return resp.json();
        }
    })
    .then(data => {
        if (!sessionStorage.getItem("aes_public_key")) {
            window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"]
            ).then(keyPair => {
            window.crypto.subtle.exportKey("spki", keyPair.publicKey).then(exportedKey => {
                // Exported as ArrayBuffer in SPKI format, encode to base64
                const uint8Array = new Uint8Array(exportedKey);
                let binary = "";
                for (let i = 0; i < uint8Array.byteLength; i++) {
                binary += String.fromCharCode(uint8Array[i]);
                }
                const base64Key = window.btoa(binary);
                sessionStorage.setItem("aes_public_key", base64Key);
            });
            });
        }
    });
  }, []);

  const fetchFiles = () => fetch("http://localhost:8080/users/files", {
        method: 'GET',
        credentials: 'include',
        headers: {
            "Content-Type": "application/json"
        }
    })
    .then(resp => resp.json())
    .then(data => {
        console.log(data.files);
        if (Array.isArray(data.files)) {
            setFiles(
                data.files.map((file: any) => ({
                    FileName: file.FileName,
                    LastModified: file.LastModified
                }))
            );
        }
    });

  useEffect(() => {
    fetchFiles();
  }, []);


  return (
    <div className="flex items-center justify-center min-h-screen bg-purple-950">
    <div className="flex flex-col items-center space-y-4 mr-6 -mt-105">
        <label htmlFor="file-upload" className="px-12 py-6 text-2xl bg-blue-800 hover:bg-blue-900 text-white rounded-xl shadow-lg cursor-pointer w-full text-center">
            Upload
            <input
                id="file-upload"
                type="file"
                className="hidden"
                // @ts-ignore
                webkitdirectory="true"
                onChange={(e) => {
                    // handle file upload here
                    console.log(Array.from(e.target.files || []));
                }}
            />
        </label>
        <button className="px-12 py-6 text-2xl bg-blue-800 hover:bg-blue-900 text-white rounded-xl shadow-lg cursor-pointer w-full"
            onClick={downloadFiles}>
            Download
        </button>
    </div>
      <div className="flex flex-col items-center justify-center bg-blue-500 rounded-2xl shadow-lg p-8 w-[80%] h-150 stext-black">
        <div className="w-full h-full overflow-auto">
            <Dropzone
                noClick
            >
                {({ getRootProps, getInputProps, isDragActive, isDragAccept, isDragReject }) => (
                    <div
                        {...getRootProps({
                            onDrop: undefined, // disable Dropzone's default onDrop
                            onDragOver: (e: React.DragEvent) => e.preventDefault(),
                            onDrop: (event: React.DragEvent) => {
                                event.preventDefault();
                                const items = event.dataTransfer.items;
                                const droppedFiles: string[] = [];
                                let pending = 0;
                                const fileMetadatas: FileMetadata[] = [];

                                function traverseFileTree(item: any, path = "") {
                                    let uploadStarted = false;
                                    if (item.isFile) {
                                        pending++;
                                        item.file(async (file: File) => {
                                            let file_metadata = {
                                                ...file,
                                                fullPath: path + file.name,
                                                uploadDate: new Date()                                                
                                            };
                                            droppedFiles.push(path + file.name);

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

                                            const encoder = new TextEncoder();
                                            const ivBytes = window.crypto.getRandomValues(new Uint8Array(12));
                                            const fileBlob = new Blob([file]);
                                            const fileType = file.type;

                                            const aesKey = await window.crypto.subtle.generateKey(
                                                {
                                                    name: "AES-GCM",
                                                    length: 256,
                                                },
                                                true,
                                                ["encrypt", "decrypt"]
                                            );

                                            const encryptedData = await window.crypto.subtle.encrypt(
                                                {
                                                    name: "AES-GCM",
                                                    iv: ivBytes,
                                                },
                                                aesKey,
                                                await fileBlob.arrayBuffer()
                                            );

                                            // Encrypt the private key using AES-GCM
                                            const arrayBuffer = await file.arrayBuffer();
                                            const encryptedKeyBuffer = await window.crypto.subtle.encrypt(
                                                {
                                                    name: "AES-GCM",
                                                    iv: ivBytes
                                                },
                                                aesKey,
                                                arrayBuffer
                                            );                                            

                                            // Import the public key string as a CryptoKey
                                            const aesPublicKeyBase64 = sessionStorage.getItem("aes_public_key");
                                            if (!aesPublicKeyBase64) {
                                                throw new Error("aes_public_key not found in sessionStorage");
                                            }

                                            const importedPublicKey = await window.crypto.subtle.importKey(
                                                "spki",
                                                base64ToArrayBuffer(aesPublicKeyBase64),
                                                {
                                                    name: "RSA-OAEP",
                                                    hash: "SHA-256"
                                                },
                                                false,
                                                ["encrypt"]
                                            );

                                            console.log("after imported public key");

                                            let encryptedAesKeyBuffer = await window.crypto.subtle.encrypt(
                                                { name: "RSA-OAEP" },
                                                importedPublicKey,
                                                await window.crypto.subtle.exportKey("raw", aesKey)
                                            );

                                            const iv = arrayBufferToBase64(ivBytes.buffer);
                                            const encryptedAesKey = arrayBufferToBase64(encryptedAesKeyBuffer);
                                            const encryptedFile = arrayBufferToBase64(encryptedData);

                                            file_metadata = {
                                                ...file_metadata,
                                                iv: iv,
                                                encryptedAesKey: encryptedAesKey,
                                                encryptedFile: encryptedFile,
                                                fileType: fileType
                                            }
                                            fileMetadatas.push(file_metadata);

                                            pending--;

                                            if(!uploadStarted && pending === 0){
                                                uploadStarted = true;
                                                console.dir(fileMetadatas);
                                                try {
                                                    const response = await fetch("http://localhost:8080/users/upload", {
                                                        method: "POST",
                                                        credentials: "include",
                                                        headers: {
                                                            "Content-Type": "application/json"
                                                        },
                                                        body: JSON.stringify({
                                                            file_metadata: fileMetadatas
                                                        })
                                                    });
                                                    if(response.ok){
                                                        fetchFiles();
                                                    }
                                                } catch (error) {
                                                    console.error('Error fetching /users/upload:', error);
                                                }
                                            }
                                        });
                                    } else if (item.isDirectory) {
                                        const dirReader = item.createReader();
                                        dirReader.readEntries((entries: any[]) => {
                                            entries.forEach(entry => traverseFileTree(entry, path + item.name + "/"));
                                        });
                                    }
                                }

                                for (let i = 0; i < items.length; i++) {
                                    const item = items[i].webkitGetAsEntry && items[i].webkitGetAsEntry();
                                    if (item) {
                                        traverseFileTree(item);
                                    }
                                }
                            }
                        })}
                        className={`transition-colors duration-200 ${
                            isDragActive ? "bg-blue-700" : "bg-blue-600"
                        } min-w-full rounded-lg`}
                        style={{ cursor: "pointer", position: "relative" }}
                    >
                        <input {...getInputProps()} />
                        <table className="min-w-full rounded-lg">
                            <thead>
                                <tr>
                                    <th className="px-4 py-2 text-left">
                                        <input type="checkbox" onClick={selectAllFiles}/>
                                    </th>
                                    <th className="px-4 py-2 text-left text-black">Name</th>
                                    <th className="px-4 py-2 text-left text-black">Last Modified</th>
                                </tr>
                            </thead>
                            <tbody>
                                {files.map((file, idx) => (
                                    <tr
                                        className={`border-t transition-colors duration-150 hover:bg-blue-800`}
                                        key={file.FileName || idx}
                                    >
                                        <td className="px-4 py-2">
                                            <input
                                                type="checkbox"
                                                checked={selectedFiles.includes(file.FileName)}
                                                onChange={() => {
                                                    setSelectedFiles(prev =>
                                                        prev.includes(file.FileName)
                                                            ? prev.filter(f => f !== file.FileName)
                                                            : [...prev, file.FileName]
                                                    );
                                                }}
                                                title={`Select file ${file}`}
                                            />
                                        </td>
                                        <td className="px-4 py-2 text-black">{file.FileName}</td>
                                        <td className="px-4 py-2 text-black">
                                            {file.LastModified && !isNaN(new Date(file.LastModified).getTime())
                                            ? new Date(file.LastModified).toLocaleString()
                                            : "loading..."
                                            }
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                        {isDragActive && (
                            <div className="absolute inset-0 flex items-center justify-center bg-blue-900 bg-opacity-40 rounded-lg pointer-events-none">
                                <span className="text-white text-lg font-bold">Drop files here...</span>
                            </div>
                        )}
                    </div>
                )}
            </Dropzone>
        </div>
      </div>
    </div>
  );
}
