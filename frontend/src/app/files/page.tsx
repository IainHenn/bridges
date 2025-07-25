"use client"
import { useState, useEffect } from "react";
import { useRouter } from 'next/navigation';
// import { decodeReply } from "next/dist/server/app-render/entry-base";
import Dropzone from 'react-dropzone'
import JSZip from "jszip";



export default function files() {

  type FilePreview = {
    FileName: string
    LastModified: string
  }
  
  const router = useRouter();
  const [files, setFiles] = useState<FilePreview[]>([]);
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const [selectAll, setSelectAll] = useState(false);
  const [publicKeyEncDec, setPublicKeyEncDec] = useState("");
  const [privateKeyEncDec, setPrivateKeyEncDec] = useState("");
  const [privateKeyStatus, setPrivateKeyStatus] = useState<null | "valid" | "invalid">(null);
  const [privateKeyStatusText, setPrivateKeyStatusText] = useState("");
  const [privateKeyStatusAnimIdx, setPrivateKeyStatusAnimIdx] = useState(0);
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

  // Animated typing effect for private key status
  useEffect(() => {
    let timeout: NodeJS.Timeout;
    if (privateKeyStatus === "valid") {
      const msg = "Private key is valid.";
      if (privateKeyStatusAnimIdx < msg.length) {
        timeout = setTimeout(() => {
          setPrivateKeyStatusText(msg.slice(0, privateKeyStatusAnimIdx + 1));
          setPrivateKeyStatusAnimIdx(privateKeyStatusAnimIdx + 1);
        }, 40);
      }
    } else if (privateKeyStatus === "invalid") {
      const msg = "Private key is not valid.";
      if (privateKeyStatusAnimIdx < msg.length) {
        timeout = setTimeout(() => {
          setPrivateKeyStatusText(msg.slice(0, privateKeyStatusAnimIdx + 1));
          setPrivateKeyStatusAnimIdx(privateKeyStatusAnimIdx + 1);
        }, 40);
      }
    } else {
      setPrivateKeyStatusText("");
      setPrivateKeyStatusAnimIdx(0);
    }
    return () => clearTimeout(timeout);
  }, [privateKeyStatus, privateKeyStatusAnimIdx]);

  // Helper to check if a base64 string is a valid PKCS8 private key
  async function isValidPrivateKey(base64: string): Promise<boolean> {
    try {
      const key = await window.crypto.subtle.importKey(
        "pkcs8",
        (() => {
          const binaryString = window.atob(base64);
          const len = binaryString.length;
          const bytes = new Uint8Array(len);
          for (let i = 0; i < len; i++) bytes[i] = binaryString.charCodeAt(i);
          return bytes.buffer;
        })(),
        {
          name: "RSA-OAEP",
          hash: "SHA-256"
        },
        false,
        ["decrypt"]
      );
      return !!key;
    } catch {
      return false;
    }
  }

const downloadFiles = async () => {
    console.log(selectedFiles);
    let zip = new JSZip();
    let foldersToZip: Record<string, any[]> = {};
    const resp = await fetch("http://localhost:8080/users/files", {
        method: "POST",
        credentials: "include",
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            selectedFiles
        })
    });
    const data = await resp.json();
    console.log("data");
    console.dir(data);
    await Promise.all(data.files.map(async (file: any) => {
        console.log(`privateKeyEncDec: ${privateKeyEncDec}`);
        const { EncryptedFile, Iv, EncryptedAesKey, FileType, FileName } = file;
        console.log("encryptedfile:", EncryptedFile);
        console.log("iv:", Iv);
        console.log("encryptedAesKey:", EncryptedAesKey);
        console.log("fileType:", FileType);
        console.log("FileName:", FileName);

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

        // Get user's private RSA key from state (base64 PKCS8)
        if (!privateKeyEncDec) {
            alert("Please upload your private key first.");
            return;
        }

        try {
            // Import the private key
            const privateKey = await window.crypto.subtle.importKey(
                "pkcs8",
                base64ToArrayBuffer(privateKeyEncDec),
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                false,
                ["decrypt"]
            );

            // Decrypt AES key with RSA private key
            const aesKeyRaw = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                privateKey,
                base64ToArrayBuffer(EncryptedAesKey)
            );

            // Import decrypted AES key
            const aesKey = await window.crypto.subtle.importKey(
                "raw",
                aesKeyRaw,
                { name: "AES-GCM" },
                false,
                ["decrypt"]
            );

            // Decrypt file data with AES key
            const decryptedContent = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: base64ToArrayBuffer(Iv)
                },
                aesKey,
                base64ToArrayBuffer(EncryptedFile)
            );

            // Then we know it's a file in a folder(s)
            if(FileName.includes("/")){
                // Take whatever is after the first "/"
                const zipPath = FileName.substring(FileName.indexOf("/") + 1);
                zip.file(zipPath, new Blob([decryptedContent], { type: FileType || "application/octet-stream" }));
                if (Object.keys(foldersToZip).includes(FileName.split("/")[0])) {
                    foldersToZip[FileName.split("/")[0]].push({"zipPath": zipPath, "decryptedContent": decryptedContent})
                } else {
                    foldersToZip[FileName.split("/")[0]] = []
                    foldersToZip[FileName.split("/")[0]].push({"zipPath": zipPath, "decryptedContent": decryptedContent})
                }
            }
            else {
                const blob = new Blob([decryptedContent], { type: FileType || "application/octet-stream" });
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
            }
        } catch (error) {
            console.error(error);
        }
    }));

    if (Object.keys(foldersToZip).length > 0) {
        Object.entries(foldersToZip).forEach(([folderName, filesList]) => {
            const folderZip = new JSZip();
            filesList.forEach(({ zipPath, decryptedContent }) => {
                folderZip.file(zipPath, new Blob([decryptedContent]));
            });
            folderZip.generateAsync({ type: "blob" }).then((content) => {
                const url = URL.createObjectURL(content);
                const a = document.createElement("a");
                a.href = url;
                a.download = `${folderName}.zip`;
                document.body.appendChild(a);
                a.click();
                setTimeout(() => {
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                }, 100);
            });
        });
    }
}

const deleteFiles = () => {
    fetch("http://localhost:8080/users/files", {
        method: "DELETE",
        credentials: "include",
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            selectedFiles
        })
    })
    .then(resp => {
        if(!resp.ok){
            console.log("bad");
            return;
        }
        return resp.json();
    })
    .then(data => {
        if (data && Array.isArray(data.files)) {
            setFiles(prevFiles =>
            prevFiles.filter(filePreview => !data.files.includes(filePreview.FileName))
            );
        }
    })
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
        console.log(data);
        setPublicKeyEncDec(data.public_key_enc_dec);
        if (!sessionStorage.getItem("aes_encrypted_key")) {
            // Encrypt a new AES key with the provided public_key_enc_dec and store it
            async function generateAndStoreAesKey() {
            // Generate AES-GCM key
            const aesKey = await window.crypto.subtle.generateKey(
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );
            console.log("A");
            // Export AES key as raw
            const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
            console.log("B");
            // Convert public_key_enc_dec (base64) to ArrayBuffer
            function base64ToArrayBuffer(base64: string): ArrayBuffer {
                const binaryString = window.atob(base64);
                const len = binaryString.length;
                const bytes = new Uint8Array(len);
                for (let i = 0; i < len; i++) {
                bytes[i] = binaryString.charCodeAt(i);
                }
                return bytes.buffer;
            }

            console.log("C: ", data.public_key_enc_dec);

            // Import RSA public key (spki)
            const publicKey = await window.crypto.subtle.importKey(
                "spki",
                base64ToArrayBuffer(data.public_key_enc_dec),
                {
                name: "RSA-OAEP",
                hash: "SHA-256"
                },
                false,
                ["encrypt"]
            );

            console.log("D");

            // Encrypt AES key with RSA public key
            const encryptedAesKey = await window.crypto.subtle.encrypt(
                { name: "RSA-OAEP" },
                publicKey,
                rawAesKey
            );

            console.log("E");

            // Convert encrypted AES key to base64
            function arrayBufferToBase64(buffer: ArrayBuffer) {
                const bytes = new Uint8Array(buffer);
                let binary = "";
                for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
                }
                return window.btoa(binary);
            }

            console.log("F");

            const encryptedAesKeyBase64 = arrayBufferToBase64(encryptedAesKey);

            console.log("G");

            // Store encrypted AES key in sessionStorage
            sessionStorage.setItem("aes_encrypted_key", encryptedAesKeyBase64);
            }

            generateAndStoreAesKey();
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
    <div className="flex items-center justify-center min-h-screen bg-black">
        <div className="flex flex-col items-center space-y-4 mr-6 -mt-45">
            <button
                className="px-12 py-6 text-2xl bg-black border-2 border-white text-white font-mono rounded-none shadow-none cursor-pointer w-full hover:bg-white hover:text-black transition-colors"
                onClick={downloadFiles}
                style={{ letterSpacing: "2px" }}
            >
            Download
            </button>
            <button
                className="px-12 py-6 text-2xl bg-black border-2 border-white text-white font-mono rounded-none shadow-none cursor-pointer w-full hover:bg-white hover:text-black transition-colors"
                onClick={deleteFiles}
                style={{ letterSpacing: "2px" }}
            >
                Delete
            </button>
            <Dropzone
                accept={{ "text/plain": [".txt"] }}
                maxFiles={1}
                multiple={false}
                onDrop={async (acceptedFiles) => {
                    try {
                        if (acceptedFiles.length === 1) {
                            const file = acceptedFiles[0];
                            const text = await file.text();
                            const json = JSON.parse(text);
                            const key = json["privateKeyBase64"];
                            setPrivateKeyEncDec(key);
                            setPrivateKeyStatus(null);
                            setPrivateKeyStatusText("");
                            setPrivateKeyStatusAnimIdx(0);
                            if (key) {
                            const valid = await isValidPrivateKey(key);
                            setPrivateKeyStatus(valid ? "valid" : "invalid");
                            setPrivateKeyStatusAnimIdx(0);
                            } else {
                                setPrivateKeyStatus("invalid");
                                setPrivateKeyStatusAnimIdx(0);
                            }
                        }
                    }

                    catch {
                        setPrivateKeyStatus("invalid");
                        setPrivateKeyStatusAnimIdx(0);
                    }
                }}
            >
                {({ getRootProps, getInputProps, isDragActive }) => (
                    <div
                        {...getRootProps()}
                        className={`mt-4 px-8 py-6 border-2 border-dashed rounded-none cursor-pointer w-full text-center font-mono transition-colors duration-200 ${
                            isDragActive
                                ? "bg-white border-black text-black"
                                : "bg-black border-white text-white"
                        }`}
                        style={{ letterSpacing: "1px" }}
                    >
                        <input {...getInputProps()} />
                        <span className="text-lg">
                            {isDragActive
                                ? "Drop your privatekey.txt here..."
                                : "Drag & drop your privatekey.txt here, or click to select"}
                        </span>
                        {/* Animated private key status below */}
                        {privateKeyStatus !== null && (
                          <div className={`mt-4 text-lg font-mono transition-colors duration-200 ${privateKeyStatus === "valid" ? "text-green-400" : "text-red-400"}`}>
                            {privateKeyStatusText}
                          </div>
                        )}
                    </div>
                )}
            </Dropzone>
        </div>
        <div className="flex flex-col items-center justify-center bg-black border-2 border-white rounded-none shadow-none p-8 w-[80%] h-150 font-mono text-white">
            <div className="w-full h-full overflow-auto">
                <Dropzone noClick>
                    {({
                        getRootProps,
                        getInputProps,
                        isDragActive,
                        isDragAccept,
                        isDragReject,
                    }) => (
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
                                                    uploadDate: new Date(),
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

                                                const ivBytes = window.crypto.getRandomValues(
                                                    new Uint8Array(12)
                                                );
                                                const fileBlob = new Blob([file]);
                                                const fileType = file.type;

                                                // Get the encrypted AES key from sessionStorage
                                                const aesEncryptedKeyBase64 =
                                                    sessionStorage.getItem("aes_encrypted_key");
                                                if (!aesEncryptedKeyBase64) {
                                                    alert(
                                                        "No AES encrypted key found in sessionStorage."
                                                    );
                                                    pending--;
                                                    return;
                                                }

                                                // Import the user's public RSA key (from publicKeyEncDec)
                                                const publicKeyBase64 = publicKeyEncDec;
                                                if (!publicKeyBase64) {
                                                    alert("No public RSA key found.");
                                                    pending--;
                                                    return;
                                                }
                                                const publicKey = await window.crypto.subtle.importKey(
                                                    "spki",
                                                    base64ToArrayBuffer(publicKeyBase64),
                                                    {
                                                        name: "RSA-OAEP",
                                                        hash: "SHA-256",
                                                    },
                                                    false,
                                                    ["encrypt"]
                                                );

                                                // Generate a new AES key for this file
                                                const aesKey = await window.crypto.subtle.generateKey(
                                                    {
                                                        name: "AES-GCM",
                                                        length: 256,
                                                    },
                                                    true,
                                                    ["encrypt", "decrypt"]
                                                );

                                                // Encrypt the file with the AES key
                                                const encryptedData = await window.crypto.subtle.encrypt(
                                                    {
                                                        name: "AES-GCM",
                                                        iv: ivBytes,
                                                    },
                                                    aesKey,
                                                    await fileBlob.arrayBuffer()
                                                );

                                                // Export and encrypt the AES key with the user's public RSA key
                                                const rawAesKey = await window.crypto.subtle.exportKey(
                                                    "raw",
                                                    aesKey
                                                );
                                                const encryptedAesKeyBuffer =
                                                    await window.crypto.subtle.encrypt(
                                                        { name: "RSA-OAEP" },
                                                        publicKey,
                                                        rawAesKey
                                                    );

                                                const iv = arrayBufferToBase64(ivBytes.buffer);
                                                const encryptedAesKey =
                                                    arrayBufferToBase64(encryptedAesKeyBuffer);
                                                const encryptedFile =
                                                    arrayBufferToBase64(encryptedData);

                                                file_metadata = {
                                                    ...file_metadata,
                                                    iv: iv,
                                                    encryptedAesKey: encryptedAesKey,
                                                    encryptedFile: encryptedFile,
                                                    fileType: fileType,
                                                    fileSize: file.size,
                                                };
                                                fileMetadatas.push(file_metadata);

                                                pending--;

                                                if (!uploadStarted && pending === 0) {
                                                    uploadStarted = true;
                                                    console.dir(fileMetadatas);
                                                    try {
                                                        const response = await fetch(
                                                            "http://localhost:8080/users/upload",
                                                            {
                                                                method: "POST",
                                                                credentials: "include",
                                                                headers: {
                                                                    "Content-Type": "application/json",
                                                                },
                                                                body: JSON.stringify({
                                                                    file_metadata: fileMetadatas,
                                                                }),
                                                            }
                                                        );
                                                        if (response.ok) {
                                                            fetchFiles();
                                                        }
                                                    } catch (error) {
                                                        console.error(
                                                            "Error fetching /users/upload:",
                                                            error
                                                        );
                                                    }
                                                }
                                            });
                                        } else if (item.isDirectory) {
                                            const dirReader = item.createReader();
                                            dirReader.readEntries((entries: any[]) => {
                                                entries.forEach((entry) =>
                                                    traverseFileTree(entry, path + item.name + "/")
                                                );
                                            });
                                        }
                                    }

                                    for (let i = 0; i < items.length; i++) {
                                        const item =
                                            items[i].webkitGetAsEntry && items[i].webkitGetAsEntry();
                                        if (item) {
                                            traverseFileTree(item);
                                        }
                                    }
                                },
                            })}
                            className={`transition-colors duration-200 ${
                                isDragActive
                                    ? "bg-white text-black border-black"
                                    : "bg-black text-white border-white"
                            } min-w-full border-2 rounded-none font-mono`}
                            style={{
                                cursor: "pointer",
                                position: "relative",
                                fontFamily: "monospace",
                                fontSize: "1rem",
                            }}
                        >
                            <input {...getInputProps()} />
                            <table className="min-w-full rounded-none font-mono border-separate border-spacing-0">
                                <thead>
                                    <tr>
                                        <th className="px-4 py-2 text-left border-b-2 border-white">
                                            <input
                                                type="checkbox"
                                                onClick={selectAllFiles}
                                                className="accent-white"
                                            />
                                        </th>
                                        <th className="px-4 py-2 text-left border-b-2 border-white text-white font-mono">
                                            Name
                                        </th>
                                        <th className="px-4 py-2 text-left border-b-2 border-white text-white font-mono">
                                            Last Modified
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {files.map((file, idx) => (
                                        <tr
                                            className={`border-t border-white transition-colors duration-150 hover:bg-white hover:text-black`}
                                            key={file.FileName || idx}
                                        >
                                            <td className="px-4 py-2">
                                                <input
                                                    type="checkbox"
                                                    checked={selectedFiles.includes(file.FileName)}
                                                    onChange={() => {
                                                        setSelectedFiles((prev) =>
                                                            prev.includes(file.FileName)
                                                                ? prev.filter((f) => f !== file.FileName)
                                                                : [...prev, file.FileName]
                                                        );
                                                    }}
                                                    title={`Select file ${file}`}
                                                    className="accent-white"
                                                />
                                            </td>
                                            <td className="px-4 py-2 text-white font-mono">
                                                {file.FileName}
                                            </td>
                                            <td className="px-4 py-2 text-white font-mono">
                                                {file.LastModified &&
                                                !isNaN(new Date(file.LastModified).getTime())
                                                    ? new Date(file.LastModified).toLocaleString()
                                                    : "loading..."}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                            {isDragActive && (
                                <div className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-80 rounded-none pointer-events-none border-2 border-dashed border-white">
                                    <span className="text-white text-lg font-bold font-mono">
                                        Drop files here...
                                    </span>
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
