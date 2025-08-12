"use client"
import { useState, useEffect } from "react";
import { useRouter } from 'next/navigation';
// import { decodeReply } from "next/dist/server/app-render/entry-base";
import Dropzone from 'react-dropzone'
import JSZip from "jszip";
import InboxModal from "../inbox/InboxModal";
import { AnyARecord } from "dns";



export default function inbox() {
    const [inboxModal, setInboxModal] = useState(true);

    return (
        <InboxModal/>
    )
}