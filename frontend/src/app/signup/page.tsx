"use client"
import { useState } from "react";
import { useRouter } from 'next/navigation';


export default function SignUp() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const router = useRouter();

  const renderSignUp = (event: React.FormEvent) => {
    event.preventDefault();
    fetch("http://localhost:8080/users", {
      method: "POST",
      body: JSON.stringify({ "email": email, "password": password })
    })
      .then(response => {
        if(response.status == 201){
          console.log("User created");
        } else {
          console.log(`Failed to create user: ${response.status}`)
        }
      })
      .catch(error => {
        console.error("Error:", error);
      });
  }
  const sss = () => {
    router.push('/signup');
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-purple-950">
      <div className="bg-blue-500 rounded-2xl shadow-lg p-8 w-[30%] h-85 text-black">
          <form className="flex flex-col space-y-6" onClick={renderSignUp}>
            <div className="flex flex-col space-y-2">
              <label htmlFor="email" className="text-white font-semibold">
              Email
              </label>
              <input
              id="email"
              type="email"
              className="bg-gray-100 text-black placeholder-gray-500 hover:bg-gray-600 hover:placeholder-black rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400 transition"
              placeholder="Enter your email"
              autoComplete="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              />
            </div>
            <div className="flex flex-col space-y-2">
              <label htmlFor="password" className="text-white font-semibold">
                Password
              </label>
              <input
                id="password"
                type="password"
                className="bg-gray-100 text-black placeholder-gray-500 hover:bg-gray-600 hover:placeholder-black rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400 transition"
                placeholder="Enter your password"
                autoComplete="current-password"
                value={password}
                onChange={e => setPassword(e.target.value)}
              />
            </div>
            <button
              type="button"
              className="bg-purple-700 hover:bg-purple-800 text-white font-bold py-2 rounded-md transition w-full mt-4"
            >
            Sign Up
            </button>
            </form>
      </div>
    </div>
  );
}
