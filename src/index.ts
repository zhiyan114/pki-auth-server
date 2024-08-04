import { createServer } from "https";
import { checkCA, domainCheck, getAllCAContent, setCORS } from "./utils";
import { config } from "dotenv";
import { readdirSync } from "fs";
import { TLSSocket } from "tls";
import redis from "redis";
import { randomBytes } from "crypto";

config();
const ca_data = getAllCAContent();
console.log(`Loaded ${ca_data.length} CA certificates.`);

// Redis server
if(!process.env["REIDS_CONN"])
    throw new Error("REIDS_CONN is not set in .env (required for auth token caching)");
const redisClient = redis.createClient({
    url: process.env["REIDS_CONN"],
});

const server = createServer({
  minVersion: "TLSv1.2",
  maxVersion: "TLSv1.3",
  key: process.env["SERVER_KEY"],
  cert: process.env["SERVER_CERT"],
  ca: ca_data,
  requestCert: true,
  rejectUnauthorized: true,
  keepAlive: false,
}, async (req, res) => {

    setCORS(res);
    res.setHeader('Connection', 'close'); // NoKeepAlive

    if(!checkCA(req))
        return res.writeHead(403).end("Forbidden");
    if(!domainCheck(req))
        return res.writeHead(403).end("Forbidden");
    const socket = req.socket as TLSSocket;
    const userCert = socket.getPeerCertificate(true)
    //res.end(`ISSUER HASH: ${userCert.issuerCertificate?.fingerprint}`);
    
    // Existing Request Checks
    const existToken = await redisClient.get(`PKIAuth:FP:${userCert.fingerprint}`)
    if(existToken)
        return res.writeHead(200).end(existToken);

    // Make new request
    const randToken = randomBytes(24).toString("hex");
    await redisClient.set(`PKIAuth:FP:${userCert.fingerprint}`, randToken, {EX: 300});
    await redisClient.set(`PKIAuth:Token:${randToken}`, JSON.stringify({
        serial: userCert.serialNumber,
        CN: userCert.subject.CN,
        SubAlt: userCert.subjectaltname,
        KeyUsage: userCert.ext_key_usage,
        CA_FP: userCert.issuerCertificate?.fingerprint,
    }), {EX: 300});
})


server.listen(443, async () => {
    console.log("PKI Auth is listening...");
    await redisClient.connect();
    console.log("Redis connected.");
})