import React, { useEffect, useState} from "react";

interface UnshareFilesModalProps {
    filename: string;
    open: boolean;
    onClose: () => void;
}

export default function UnshareFilesModal({ filename, open, onClose }: UnshareFilesModalProps) {
    if (!open) return null;
    const [usersSharedWith, setUsersSharedWith] = useState([]);
    useEffect(() => {
        if (open) {
            console.log("filename: ", filename);
            fetch("http://localhost:8080/users/files/shared-with", {
                method: "POST",
                credentials: 'include',
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ filename }),
            })
            .then(resp => {
                if (resp.ok) {
                    resp.json().then(data => {
                        setUsersSharedWith(data.users || []);
                    });
                }
            });
        }
    }, [open]);
    return (
        <div className="fixed inset-0 bg-black bg-opacity-80 flex items-center justify-center z-50 font-mono"
        onClick={onClose}>
            <div className="bg-black border-2 border-white p-8 shadow-none w-[30rem]" style={{ borderRadius: 0 }}>
            <h2 className="text-xl font-bold mb-4 text-green-400">Unshare File</h2>
            <div className="mb-4 text-white font-mono">
                Filename: <span className="font-bold">{filename}</span>
            </div>
            <div className="mb-6 max-h-48 overflow-y-auto border border-white rounded-none">
                {usersSharedWith.length === 0 ? (
                <div className="text-gray-400 text-sm px-2 py-4">No users to unshare with.</div>
                ) : (
                usersSharedWith.map((user: string) => (
                    <div key={user} className="flex items-center justify-between px-2 py-2 border-b border-white last:border-b-0">
                    <span className="text-white">{user}</span>
                    <button
                        className="bg-red-400 border-2 border-black text-black px-3 py-1 font-mono transition-colors duration-150 hover:bg-black hover:text-white"
                        style={{ borderRadius: 0 }}
                        onClick={() => {
                        fetch("http://localhost:8080/users/files/unshare", {
                            method: "DELETE",
                            credentials: 'include',
                            headers: {
                            "Content-Type": "application/json",
                            },
                            body: JSON.stringify({ "recipientEmail": user, "fileName": filename }),
                        }).then(resp => {
                            if (resp.ok) {
                            setUsersSharedWith(prev => prev.filter(u => u !== user));
                            }
                        });
                        }}
                    >
                        Remove
                    </button>
                    </div>
                ))
                )}
            </div>
            <button
                className="bg-white text-black px-4 py-2 border-2 border-black font-mono w-full"
                style={{ borderRadius: 0 }}
                onClick={onClose}
            >
                Close
            </button>
            </div>
        </div>
    );
}
