import { createServer } from "https";
import { checkCA, domainCheck, getAllCAContent, setCORS } from "./utils";
import { config } from "dotenv";
import { readdirSync } from "fs";
import { TLSSocket } from "tls";

config();
const ca_data = getAllCAContent();
console.log(`Loaded ${ca_data.length} CA certificates.`);
const server = createServer({
  minVersion: "TLSv1.2",
  maxVersion: "TLSv1.3",
  key: process.env["SERVER_KEY"],
  cert: process.env["SERVER_CERT"],
  ca: ca_data,
  requestCert: true,
  rejectUnauthorized: true,
  keepAlive: false,
}, (req, res) => {
    setCORS(res);
    res.setHeader('Connection', 'close'); // NoKeepAlive

    if(!checkCA(req))
        return res.writeHead(403).end("Forbidden");
    if(!domainCheck(req))
        return res.writeHead(403).end("Forbidden");
    const socket = req.socket as TLSSocket;
    const userCert = socket.getPeerCertificate(true)
    res.end(`ISSUER HASH: ${userCert.issuerCertificate?.fingerprint}`);
})


server.listen(443, () => {
    console.log("PKI Auth is listening...");
})