"use client"
import Image from "next/image";
import { useState } from "react";
import { useRouter } from 'next/navigation';
import { RouterContext } from "next/dist/shared/lib/router-context.shared-runtime";


export default function Home() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const router = useRouter();

  const signIn = async (event: React.FormEvent) => {
    event.preventDefault();
    const form = event.target as HTMLFormElement;
    setEmail(form.email.value);
    setPassword(form.password.value);
    event.preventDefault();
    fetch("http://localhost:8080/sessions", {
      method: "POST",
      body: JSON.stringify({ "email": email, "password": password })
    })
      .then(async response => {
        if(response.status == 200){
          const tokenResponse = await fetch("http://localhost:8080/tokens", {
            method: "POST",
            body: JSON.stringify({ "email": email, "password": password })
          });
          if(tokenResponse.ok){
            const tokenData = await tokenResponse.json();
            // Store token in httpOnly cookie via server (client JS cannot set httpOnly cookies directly)
            // Send token to an API route that sets the cookie
            await fetch("/token-cookies", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ token: tokenData.token })
            });
          } else {
            console.log("failed to generate user token");
          }
          router.push('/validate');
        } else {
          console.log(`Failed to login user: ${response.status}`)
        }
      })
      .catch(error => {
        console.error("Error:", error);
      });
  }
  const signUp = () => {
    router.push('/signup');
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-black">
      <div className="bg-black border-2 border-white rounded-none shadow-none p-8 w-[30%] min-w-[350px] font-mono text-white">
        <form className="flex flex-col space-y-6" onSubmit={signIn}>
          <div className="flex flex-col space-y-2">
            <label htmlFor="email" className="text-white font-mono tracking-widest">
              Email
            </label>
            <input
              id="email"
              type="email"
              name="email"
              className="bg-black border-2 border-white text-white font-mono px-4 py-2 rounded-none placeholder-gray-400 focus:outline-none focus:border-white focus:bg-black transition-colors"
              placeholder="Enter your email"
              autoComplete="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              style={{ letterSpacing: "1px" }}
            />
          </div>
          <div className="flex flex-col space-y-2">
            <label htmlFor="password" className="text-white font-mono tracking-widest">
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              className="bg-black border-2 border-white text-white font-mono px-4 py-2 rounded-none placeholder-gray-400 focus:outline-none focus:border-white focus:bg-black transition-colors"
              placeholder="Enter your password"
              autoComplete="current-password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              style={{ letterSpacing: "1px" }}
            />
          </div>
          <button
            type="submit"
            className="bg-black border-2 border-white text-white font-mono font-bold py-2 rounded-none transition-colors w-full hover:bg-white hover:text-black"
            style={{ letterSpacing: "2px" }}
          >
            Sign In
          </button>
        </form>
        <button
          type="button"
          className="bg-black border-2 border-white text-white font-mono font-bold py-2 rounded-none transition-colors w-full mt-4 hover:bg-white hover:text-black"
          onClick={signUp}
          style={{ letterSpacing: "2px" }}
        >
          Sign Up
        </button>
      </div>
    </div>
  );
}
