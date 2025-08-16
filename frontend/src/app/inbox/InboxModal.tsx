import { useEffect, useState } from "react";

export default function InboxModal() {
    const [files, setFiles] = useState<any[]>([]);
    const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
    const [loading, setLoading] = useState<boolean>(false);
    const [notif, setNotif] = useState<string | null>(null);
    const [notifProgress, setNotifProgress] = useState(0);

    useEffect(() => {
        setLoading(true);
        fetch("http://localhost:8080/users/files/inbox", {
            method: 'GET',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
        })
            .then(resp => {
                if (resp.ok) {
                    resp.json().then(data => {
                        setFiles(data.inbox_files || []);
                        setLoading(false);
                    });
                } else {
                    setFiles([]);
                    setLoading(false);
                }
            })
            .catch(() => {
                setFiles([]);
                setLoading(false);
            });
    }, []);

    // Notification progress effect
    useEffect(() => {
        if (notif) {
            setNotifProgress(0);
            const interval = setInterval(() => {
                setNotifProgress(prev => {
                    if (prev >= 100) {
                        setNotif(null);
                        clearInterval(interval);
                        return 100;
                    }
                    return prev + 2;
                });
            }, 30); // ~1.5s total
            return () => clearInterval(interval);
        }
    }, [notif]);

    const selectAllFiles = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.checked) {
            setSelectedFiles(files.map(f => f.FileName));
        } else {
            setSelectedFiles([]);
        }
    };


    return (
        <div className="fixed inset-0 bg-black bg-opacity-80 flex items-center justify-center z-50 font-mono">
            <div className="bg-black border-2 border-white p-8 shadow-none min-w-[600px]" style={{ borderRadius: 0 }}>
                {loading ? (
                    <div className="text-green-400 font-mono text-lg mb-4">Loading...</div>
                ) : (
                    <table
                        className="min-w-full font-mono border-separate border-spacing-0 bg-black border-2 border-white"
                        style={{ borderRadius: 0, fontFamily: "monospace" }}
                    >
                        <thead>
                            <tr>
                                <th className="px-4 py-2 text-left border-b-2 border-white bg-black text-white font-mono" style={{ borderRadius: 0 }}>
                                    <input
                                        type="checkbox"
                                        checked={selectedFiles.length === files.length && files.length > 0}
                                        onChange={selectAllFiles}
                                        className="accent-white"
                                    />
                                </th>
                                <th className="px-4 py-2 text-left border-b-2 border-white bg-black text-white font-mono" style={{ borderRadius: 0 }}>
                                    Name
                                </th>
                                <th className="px-4 py-2 text-left border-b-2 border-white bg-black text-white font-mono" style={{ borderRadius: 0 }}>
                                    Last Modified
                                </th>
                                <th className="px-4 py-2 text-left border-b-2 border-white bg-black text-white font-mono" style={{ borderRadius: 0 }}>
                                    Sent By
                                </th>
                                <th className="px-4 py-2 text-left border-b-2 border-white bg-black text-white font-mono" style={{ borderRadius: 0 }}>
                                    Accept/Decline
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {files.map((file, idx) => (
                                <tr
                                    key={file.FileName || idx}
                                    className="border-t-2 border-white transition-colors duration-150 hover:bg-white hover:text-black"
                                    style={{ borderRadius: 0 }}
                                >
                                    <td className="px-4 py-2 bg-black text-white font-mono transition-colors duration-150 hover:bg-white hover:text-black" style={{ borderRadius: 0 }}>
                                        <input
                                            type="checkbox"
                                            checked={selectedFiles.includes(file.fileName)}
                                            onChange={() => {
                                                setSelectedFiles((prev) =>
                                                    prev.includes(file.fileName)
                                                        ? prev.filter((f) => f !== file.fileName)
                                                        : [...prev, file.fileName]
                                                );
                                            }}
                                            title={`Select file ${file.fileName}`}
                                            className="accent-white"
                                        />
                                    </td>
                                    <td className="px-4 py-2 bg-black text-white font-mono transition-colors duration-150 hover:bg-white hover:text-black" style={{ borderRadius: 0 }}>
                                        {file.fileName}
                                    </td>
                                    <td className="px-4 py-2 bg-black text-white font-mono transition-colors duration-150 hover:bg-white hover:text-black" style={{ borderRadius: 0 }}>
                                        {file.lastModified}
                                    </td>
                                    <td className="px-4 py-2 bg-black text-white font-mono transition-colors duration-150 hover:bg-white hover:text-black" style={{ borderRadius: 0 }}>
                                        {file.ownerEmail}
                                    </td>
                                    <td className="px-4 py-2 bg-black text-white font-mono transition-colors duration-150 hover:bg-white hover:text-black" style={{ borderRadius: 0 }}>
                                        <button
                                            className="bg-green-400 border-2 border-black text-black px-3 py-1 font-mono mr-2 transition-colors duration-150 hover:bg-black hover:text-white"
                                            style={{ borderRadius: 0 }}
                                            onClick={() => {
                                                // Accept file
                                                fetch("http://localhost:8080/users/files/inbox", {
                                                    method: 'POST',
                                                    credentials: 'include',
                                                    headers: {
                                                        'Content-Type': 'application/json'
                                                    },
                                                    body: JSON.stringify({"files": [file]})
                                                })
                                                .then(resp => {
                                                    if(resp.ok){
                                                        setNotif(`Accepted "${file.fileName}"`);
                                                        setFiles(prev => prev.filter(f => f.fileName !== file.fileName))
                                                    } else {
                                                        setNotif("Failed to accept file");
                                                    }
                                                })
                                            }}
                                        >
                                            Accept
                                        </button>
                                        <button
                                            className="bg-red-400 border-2 border-black text-black px-3 py-1 font-mono transition-colors duration-150 hover:bg-black hover:text-white"
                                            style={{ borderRadius: 0 }}
                                            onClick={() => {
                                                fetch("http://localhost:8080/users/files/inbox", {
                                                    method: 'DELETE',
                                                    credentials: 'include',
                                                    headers: {
                                                        'Content-Type': 'application/json'
                                                    },
                                                    body: JSON.stringify({"files": [file.fileName]})
                                                })
                                                .then(resp => {
                                                    if(resp.ok){
                                                        setNotif(`Deleted "${file.fileName}"`);
                                                        setFiles(prev => prev.filter(f => f.fileName !== file.fileName))
                                                    } else {
                                                        setNotif("Failed to delete file");
                                                    }
                                                })
                                            }}
                                        >
                                            Decline
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
            {/* Notification box */}
            {notif && (
                <div className="fixed bottom-8 left-1/2 transform -translate-x-1/2 bg-black border-2 border-white px-8 py-4 font-mono text-white text-lg shadow-none"
                    style={{ borderRadius: 0, minWidth: 300, zIndex: 100 }}>
                    <div className="mb-2">{notif}</div>
                    <div className="w-full h-2 bg-white relative" style={{ borderRadius: 0 }}>
                        <div
                            className="h-2 bg-green-400 transition-all duration-75"
                            style={{
                                width: `${notifProgress}%`,
                                borderRadius: 0,
                                position: "absolute",
                                left: 0,
                                top: 0
                            }}
                        ></div>
                    </div>
                </div>
            )}
        </div>
    );
}