"use client"
import { useState } from "react";
import { useRouter } from 'next/navigation';
import { decodeReply } from "next/dist/server/app-render/entry-base";


export default function Dashboard() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-purple-950">
      <div className="bg-blue-500 rounded-2xl shadow-lg p-8 w-[30%] h-85 text-black">
        <p>hi</p>
      </div>
    </div>
  );
}
