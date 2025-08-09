import {useState} from "react";

export default function ShareFilesModal({open, onClose, onShare}){
    const [email, setEmail] = useState("");
    const [emails, setEmails] = useState<string[]>([]);
    const [error, setError] = useState("");

    const handleAddEmail = async () => {
        // Simple email validation
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        setError("Invalid email format.");
        return;
        }
        // TODO: Check if email exists in DB via API
        const resp = await fetch("http://localhost:8080/users/exists", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: 'include',
        body: JSON.stringify({ email }),
        });
        if (!resp.ok) {
        setError("Email not found.");
        return;
        }
        setEmails([...emails, email]);
        setEmail("");
        setError("");
    };

    const handleShare = () => {
        onShare(emails);
        onClose();
    };

    if (!open) return null;
    return (
        <div className="fixed inset-0 bg-black bg-opacity-80 flex items-center justify-center z-50 font-mono">
            <div className="bg-black border-2 border-white p-8 shadow-none w-96"
                style={{ borderRadius: 0, fontFamily: "monospace" }}>
                <h2 className="text-2xl font-bold mb-4 text-green-400 tracking-wide" style={{ letterSpacing: "2px" }}>
                    Share Files
                </h2>
                <input
                    type="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    placeholder="Enter user email"
                    className="w-full p-2 border-2 border-white bg-black text-white mb-2 font-mono"
                    style={{ borderRadius: 0 }}
                />
                <button
                    onClick={handleAddEmail}
                    className="bg-green-400 text-black px-4 py-2 border-2 border-black font-mono mb-2 w-full"
                    style={{ borderRadius: 0, letterSpacing: "1px" }}
                >
                    Add Email
                </button>
                {error && <div className="text-red-400 mb-2 font-mono">{error}</div>}
                <div className="mb-4 flex flex-wrap">
                    {emails.map(e => (
                        <span key={e}
                            className="bg-white text-black px-2 py-1 border-2 border-black font-mono mr-2 mb-2"
                            style={{ borderRadius: 0, fontSize: "0.95rem" }}>
                            {e}
                        </span>
                    ))}
                </div>
                <button
                    onClick={handleShare}
                    className={`bg-blue-500 text-white px-4 py-2 border-2 border-white font-mono w-full mb-2 transition-colors duration-150 ${
                        emails.length === 0 ? "opacity-50 cursor-not-allowed" : "hover:bg-white hover:text-black"
                    }`}
                    style={{ borderRadius: 0, letterSpacing: "1px" }}
                    disabled={emails.length === 0}
                >
                    Share Selected Files
                </button>
                <button
                    onClick={onClose}
                    className="w-full py-2 mt-2 text-white bg-black border-2 border-white font-mono hover:bg-white hover:text-black transition-colors"
                    style={{ borderRadius: 0, letterSpacing: "1px" }}
                >
                    Cancel
                </button>
            </div>
        </div>
    );
}