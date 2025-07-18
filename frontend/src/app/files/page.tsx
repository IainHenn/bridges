"use client"
import { useState, useEffect } from "react";
import { useRouter } from 'next/navigation';
import { decodeReply } from "next/dist/server/app-render/entry-base";
import Dropzone from 'react-dropzone'


export default function files() {
  const [files, setFiles] = useState(['example.txt']);
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const [selectAll, setSelectAll] = useState(false);

  const selectAllFiles = () => {

    if(selectAll == false){
        setSelectedFiles(files);
        setSelectAll(true);
    }
    else {
    setSelectedFiles([]);
    setSelectAll(false);
    }
  }
  return (
    <div className="flex items-center justify-center min-h-screen bg-purple-950">
    <div className="flex flex-col items-center space-y-4 mr-6 -mt-105">
        <label htmlFor="file-upload" className="px-12 py-6 text-2xl bg-blue-800 hover:bg-blue-900 text-white rounded-xl shadow-lg cursor-pointer w-full text-center">
            Upload
            <input
                id="file-upload"
                type="file"
                className="hidden"
                onChange={(e) => {
                    // handle file upload here
                    const file = e.target.files?.[0];
                    if (file) {
                        // You can process the file here
                        console.log("Selected file:", file);
                    }
                }}
            />
        </label>
        <button className="px-12 py-6 text-2xl bg-blue-800 hover:bg-blue-900 text-white rounded-xl shadow-lg cursor-pointer w-full">
            Download
        </button>
    </div>
      <div className="flex flex-col items-center justify-center bg-blue-500 rounded-2xl shadow-lg p-8 w-[80%] h-150 stext-black">
        <div className="w-full h-full overflow-auto">
            <Dropzone
                noClick
                onDrop={acceptedFiles => {
                    // handle dropped files here
                    if (acceptedFiles.length > 0) {
                        //This is wrong fix later
                        setFiles(prev => [...prev, ...acceptedFiles.map(f => f.name)]);
                    }
                }}
            >
                {({ getRootProps, getInputProps, isDragActive, isDragAccept, isDragReject }) => (
                    <div
                        {...getRootProps()}
                        className={`transition-colors duration-200 ${
                            isDragActive ? "bg-blue-700" : "bg-blue-600"
                        } min-w-full rounded-lg`}
                        style={{ cursor: "pointer" }}
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
                                        key={file || idx}
                                    >
                                        <td className="px-4 py-2">
                                            <input
                                                type="checkbox"
                                                checked={selectedFiles.includes(file)}
                                                onChange={() => {
                                                    setSelectedFiles(prev =>
                                                        prev.includes(file)
                                                            ? prev.filter(f => f !== file)
                                                            : [...prev, file]
                                                    );
                                                }}
                                                title={`Select file ${file}`}
                                            />
                                        </td>
                                        <td className="px-4 py-2 text-black">{file}</td>
                                        <td className="px-4 py-2 text-black">2024-06-10 12:34</td>
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
