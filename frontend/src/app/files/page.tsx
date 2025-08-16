"use client"
import { useState, useEffect } from "react";
import { useRouter } from 'next/navigation';
// import { decodeReply } from "next/dist/server/app-render/entry-base";
import Dropzone from 'react-dropzone'
import JSZip from "jszip";
import ShareFilesModal from "./ShareFilesModal";
import InboxModal from "../inbox/InboxModal";
import { AnyARecord } from "dns";



export default function files() {

  const [showShareFilesModal, setShowShareFilesModal] = useState(false);

  type FilePreview = {
    FileName: string
    LastModified: string
    OwnedBy: string
  }
  
  const router = useRouter();
  const [files, setFiles] = useState<FilePreview[]>([]);
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const [selectAll, setSelectAll] = useState(false);
  const [publicKeyEncDec, setPublicKeyEncDec] = useState("");
  const [hostEmail, setHostEmail] = useState("");
  const [privateKeyEncDec, setPrivateKeyEncDec] = useState("");
  const [privateKeyStatus, setPrivateKeyStatus] = useState<null | "valid" | "invalid">(null);
  const [privateKeyStatusText, setPrivateKeyStatusText] = useState("");
  const [privateKeyStatusAnimIdx, setPrivateKeyStatusAnimIdx] = useState(0);
  const [downloadProgress, setDownloadProgress] = useState(0);
  const [isDownloading, setIsDownloading] = useState(false);
  const [loading, setLoading] = useState(true); // loading state
  const [loadingDots, setLoadingDots] = useState(0);

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


  function signOut() {
    fetch("http://localhost:8080/users", {
        method: "GET",
        credentials: "include"
    })
    .then(resp => {
        if(resp.ok){
            router.push("/")
        }
    })
  }

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
    setIsDownloading(true);
    setDownloadProgress(0);

    let matchedFiles = files.filter(file => selectedFiles.includes(file.FileName));

    console.log("matchedFiles: ", matchedFiles);


    // Fetch file metadata for selected files
    const metadataResp = await fetch("http://localhost:8080/users/files/metadata", {
        method: "POST",
        credentials: "include",
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ matchedFiles })
    });

    const metadataData = await metadataResp.json();
    if (!metadataData || !Array.isArray(metadataData.files)) {
        alert("Failed to fetch file metadata.");
        return;
    }

    console.log("metadataData: ", metadataData);

    let zip = new JSZip();
    let foldersToZip: Record<string, any[]> = {};

    let totalFiles = metadataData.files.length;
    let currentFileIdx = 0;

    for (const fileMeta of metadataData.files) {
        const s3Path = fileMeta.S3Path || fileMeta.FileName;
        const fileName = fileMeta.FileName;
        const fileType = fileMeta.FileType;

        // Stream file bytes from backend using s3Path
        const resp = await fetch("http://localhost:8080/users/files", {
            method: "POST",
            credentials: "include",
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ s3Path })
        });

        if (!resp.ok) {
            console.error(`Failed to fetch file: ${fileName}`);
            continue;
        }

        const contentLength = Number(resp.headers.get("Content-Length")) || 0;
        const reader = resp.body?.getReader();
        let receivedLength = 0;
        const chunks: Uint8Array[] = [];

        while (reader) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
            receivedLength += value.length;
            // Progress for current file (if contentLength known)
            if (contentLength > 0) {
                setDownloadProgress(
                    Math.min(
                        100,
                        Math.round(
                            ((currentFileIdx + receivedLength / contentLength) / totalFiles) * 100
                        )
                    )
                );
            }
        }

        // Concatenate chunks
        const encryptedFileBuffer = new Uint8Array(receivedLength);
        let position = 0;
        for (const chunk of chunks) {
        encryptedFileBuffer.set(chunk, position);
        position += chunk.length;
        }


        // Get user's private RSA key from state (base64 PKCS8)
        if (!privateKeyEncDec) {
            setIsDownloading(false);
            alert("Please upload your private key first.");
            return;
        }

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
                base64ToArrayBuffer(fileMeta.EncryptedAesKey)
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
                    iv: base64ToArrayBuffer(fileMeta.Iv)
                },
                aesKey,
                encryptedFileBuffer
            );


            // If file is in a folder, add to zip
            if (fileName.includes("/")) {
                const zipPath = fileName.substring(fileName.indexOf("/") + 1);
                zip.file(zipPath, new Blob([decryptedContent], { type: fileType || "application/octet-stream" }));
                if (Object.keys(foldersToZip).includes(fileName.split("/")[0])) {
                    foldersToZip[fileName.split("/")[0]].push({ zipPath, decryptedContent });
                } else {
                    foldersToZip[fileName.split("/")[0]] = [{ zipPath, decryptedContent }];
                }
            } else {
                // Download single file directly
                const blob = new Blob([decryptedContent], { type: fileType || "application/octet-stream" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = fileName || "downloaded_file";
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
        currentFileIdx++;
        // Progress for completed file
        setDownloadProgress(Math.round((currentFileIdx / totalFiles) * 100));
    }

    // Download folders as zip
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
};

const deleteFiles = () => {
    setIsDownloading(false);
    let matchedFiles = files.filter(file => selectedFiles.includes(file.FileName));
    fetch("http://localhost:8080/users/files", {
        method: "DELETE",
        credentials: "include",
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            matchedFiles
        })
    })
    .then(resp => {
        if(!resp.ok){
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
            setLoading(false); // authorized, stop loading
            return resp.json();
        }
    })
    .then(data => {
        setPublicKeyEncDec(data.public_key_enc_dec);
        setHostEmail(data.host_email);
        if (!sessionStorage.getItem("aes_encrypted_key")) {
            // Encrypt a new AES key with the provided public_key_enc_dec and store it
            async function generateAndStoreAesKey() {

            // Generate AES-GCM key
            const aesKey = await window.crypto.subtle.generateKey(
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );

            // Export AES key as raw
            const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);

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

            // Encrypt AES key with RSA public key
            const encryptedAesKey = await window.crypto.subtle.encrypt(
                { name: "RSA-OAEP" },
                publicKey,
                rawAesKey
            );


            // Convert encrypted AES key to base64
            function arrayBufferToBase64(buffer: ArrayBuffer) {
                const bytes = new Uint8Array(buffer);
                let binary = "";
                for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
                }
                return window.btoa(binary);
            }


            const encryptedAesKeyBase64 = arrayBufferToBase64(encryptedAesKey);


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
        if (Array.isArray(data.files)) {
            setFiles(
                data.files.map((file: any) => ({
                    FileName: file.FileName,
                    LastModified: file.LastModified,
                    OwnedBy: file.OwnedBy,
                }))
            );
        }
    });

  useEffect(() => {
    fetchFiles();
  }, []);


  return (
    <div className="flex items-center justify-center min-h-screen bg-black">
      {loading ? (
        <div className="flex flex-col items-center justify-center w-full h-full">
          <span
            className="text-green-400 font-mono text-2xl"
            style={{ letterSpacing: "2px" }}
          >
            Authorizing{" " + ".".repeat(loadingDots).padEnd(3, " ")}
          </span>
        </div>
      ) : (
        <>
          <div className="flex flex-col items-center space-y-4 mr-6 -mt-0">
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

            <button
                className="px-12 py-6 text-2xl bg-black border-2 border-white text-white font-mono rounded-none shadow-none cursor-pointer w-full hover:bg-white hover:text-black transition-colors"
                onClick={() => {setShowShareFilesModal(true)}}
                style={{ letterSpacing: "2px" }}
            >
                Share Selected Files
            </button>

            <button
                className="px-12 py-6 text-2xl bg-black border-2 border-white text-white font-mono rounded-none shadow-none cursor-pointer w-full hover:bg-white hover:text-black transition-colors"
                onClick={() => router.push("/inbox")}
                style={{ letterSpacing: "2px" }}
            >
                Inbox
            </button>

            {showShareFilesModal &&
                <ShareFilesModal
                    open={showShareFilesModal}
                    onClose={() => setShowShareFilesModal(false)}
                    onShare={(emails: string[]) => {
                        fetch("http://localhost:8080/users/files/metadata", {
                            method: 'POST',
                            credentials: 'include',
                            headers: {
                                "Content-Type": "application/json"
                            },
                            body: JSON.stringify({ selectedFiles })
                        })
                        .then(resp => {
                            if (resp.status != 200) {
                                console.log("failure");
                                return
                            } else {
                                (async () => {
                                    const dataObj = await resp.json();
                                    console.log("Shared files response:", dataObj);
                                    let sharedInfo: { [email: string]: any[] } = {};
                                    let decryptedAesKeys: any = {};

                                    // Fetch public keys for all emails
                                    const pubKeysResp = await fetch("http://localhost:8080/users/public-keys", {
                                        method: 'POST',
                                        credentials: 'include',
                                        headers: {
                                            'Content-Type': 'application/json'
                                        },
                                        body: JSON.stringify({emails})
                                    });
                                    if (!pubKeysResp.ok) {
                                        console.log("inner failure");
                                        return;
                                    }
                                    const pubKeysData = await pubKeysResp.json();
                                    const pubKeys = pubKeysData.public_keys;

                                    // Helper function
                                    function base64ToArrayBuffer(base64: string | undefined): ArrayBuffer {
                                        if (typeof base64 !== "string") {
                                            throw new Error("Invalid base64 input for base64ToArrayBuffer");
                                        }
                                        // Remove whitespace and newlines
                                        const sanitized = base64.replace(/[\r\n\s]/g, "");
                                        const binaryString = window.atob(sanitized);
                                        const len = binaryString.length;
                                        const bytes = new Uint8Array(len);
                                        for (let i = 0; i < len; i++) {
                                            bytes[i] = binaryString.charCodeAt(i);
                                        }
                                        return bytes.buffer;
                                    }

                                    for (const email of emails) {
                                        sharedInfo[email] = [];
                                        for (const file of dataObj.files) {
                                            file['hostEmail'] = hostEmail;
                                            try {
                                                // Decrypt the encrypted AES key for the file using the user's private key
                                                if (!privateKeyEncDec) {
                                                    alert("Please upload your private key first.");
                                                    return;
                                                }
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

                                                let decryptedAesKey: ArrayBuffer;
                                                if (!(file.FileName in decryptedAesKeys)) {
                                                    decryptedAesKey = await window.crypto.subtle.decrypt(
                                                        { name: "RSA-OAEP" },
                                                        privateKey,
                                                        base64ToArrayBuffer(file.EncryptedAesKey)
                                                    );
                                                    decryptedAesKeys[file.FileName] = decryptedAesKey;
                                                } else {
                                                    decryptedAesKey = decryptedAesKeys[file.FileName];
                                                }

                                                const pubKeyBase64 = pubKeys[email];
                                                const pubKey = await window.crypto.subtle.importKey(
                                                    "spki",
                                                    base64ToArrayBuffer(pubKeyBase64),
                                                    {
                                                        name: "RSA-OAEP",
                                                        hash: "SHA-256"
                                                    },
                                                    false,
                                                    ["encrypt"]
                                                );
                                                const encryptedAesKeyForRecipient = await window.crypto.subtle.encrypt(
                                                    { name: "RSA-OAEP" },
                                                    pubKey,
                                                    decryptedAesKey
                                                );
                                                file.EncryptedAesKeyForRecipient = window.btoa(
                                                    String.fromCharCode(...new Uint8Array(encryptedAesKeyForRecipient))
                                                );
                                                file.lastEncrypted = new Date().toISOString();
                                                sharedInfo[email].push(file);
                                            } catch (error) {
                                                console.error("Failed to decrypt AES key for file:", file.FileName, error);
                                            }
                                        }
                                    }
                                    console.log("Shared info: ", sharedInfo);
                                    fetch("http://localhost:8080/users/files/share", {
                                        method: 'POST',
                                        credentials: 'include',
                                        headers: {
                                            'Content-Type': 'application/json'
                                        },
                                        body: JSON.stringify({sharedInfo})
                                    })
                                    .then(resp => {
                                        if(resp.ok){
                                            console.log("Nice");
                                            /*resp.json().then(data => {
                                                // handle data if needed
                                                console.log(data);
                                            });*/
                                        }
                                        else {
                                            console.log("failed");
                                        }
                                    })
                                    console.log("success");
                                })();
                            }
                        })
                        .then(data => {
                            console.log(data);
                        })
                        setShowShareFilesModal(false);
                    }}
                />
            }
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

            <button
                className="px-12 py-6 text-2xl bg-black border-2 border-white text-white font-mono rounded-none shadow-none cursor-pointer w-full hover:bg-white hover:text-black transition-colors"
                onClick={signOut}
                style={{ letterSpacing: "2px" }}
            >
            Sign Out
            </button>
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
                                        <th className="px-4 py-2 text-left border-b-2 border-white text-white font-mono">
                                            Owned By
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
                                            <td className="px-4 py-2 text-white font-mono">
                                                {file.OwnedBy}
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
            <div className="w-full mt-4">
                {isDownloading && (
                <div className="w-full bg-gray-700 rounded h-6 relative">
                    <div
                    className="bg-green-400 h-6 rounded transition-all duration-100"
                    style={{ width: `${downloadProgress}%`}}
                    ></div>
                    <span className="absolute left-1/2 top-1/2 transform -translate-x-1/2 -translate-y-1/2 text-black font-bold font-mono text-sm">
                    {downloadProgress}%
                    </span>
                </div>
                )}
            </div>
        </div>
        </>
      )}
    </div>
  );
}
