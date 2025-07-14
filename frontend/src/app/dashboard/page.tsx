"use client"
import { useState } from "react";
import { useRouter } from 'next/navigation';
import { decodeReply } from "next/dist/server/app-render/entry-base";
import Dropzone from 'react-dropzone'


export default function Dashboard() {

  const [validated, setValidation] = useState(false);
  const [password, setPassword] = useState("");
  const [salt, setSalt] = useState("");
  const [nonce, setNonce] = useState("");
  const [encryptedKey, setEncryptedKey] = useState("");

  const handleDrop = async (acceptedFiles: File[]) => {
    const acceptedFile = acceptedFiles[0];
    let text = await acceptedFile.text();
    const buffer = await acceptedFile.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    console.log(`bytes: ${bytes}`);
    setSalt(Buffer.from(bytes.slice(0, 16)).toString('hex'));
    setNonce(Buffer.from(bytes.slice(16, 28)).toString('hex'));
    setEncryptedKey(Buffer.from(bytes.slice(28)).toString('hex'));
  }

  const validateUser = () => {
    fetch("http://localhost:8080/users/validate", {
      method: "POST",
      headers: {
      "Content-Type": "application/json"
      },
      body: JSON.stringify({
      password,
      salt,
      nonce,
      encryptedKey
      })
    })
      .then(res => res.json())
      .then(data => {
      if (data.valid) {
        setValidation(true);
      } else {
        setValidation(false);
        alert("Validation failed");
      }
      })
      .catch(() => {
      setValidation(false);
      alert("Validation error");
      });
  }
  
  return (
    <div className="flex items-center justify-center min-h-screen bg-purple-950">
      <div className="flex items-center justify-center bg-blue-500 rounded-2xl shadow-lg p-8 w-[30%] h-85 stext-black">
        <Dropzone accept={{ 'text/plain': ['.txt'] }} onDrop={handleDrop} multiple={false}>
          {({ getRootProps, getInputProps, isDragActive }) => (
            <section>
              <div
          {...getRootProps()}
          className={`flex flex-col items-center justify-center border-2 border-dashed rounded-xl p-8 transition-colors duration-200 ${
            isDragActive
              ? "border-purple-700 bg-purple-100"
              : "border-gray-300 bg-white"
          } cursor-pointer`}
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
        <input
          id="password"
          type="password"
          className="bg-gray-100 text-black placeholder-gray-500 hover:bg-gray-600 hover:placeholder-black rounded-md px-4 py-2 ml-4 focus:outline-none focus:ring-2 focus:ring-blue-400 transition"
          placeholder="Enter your password"
          autoComplete="current-password"
          value={password}
          onChange={e => setPassword(e.target.value)}
        />
        <button
          onClick={validateUser}
          className="bg-purple-700 hover:bg-purple-800 text-white font-bold py-2 rounded-md transition w-full mt-4"
        >
        Validate
        </button>
      </div>
    </div>
  );
}
