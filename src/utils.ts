import { IncomingMessage, ServerResponse } from 'http';
import { allow_domain } from '../config.json';
import { TLSSocket } from 'tls';
import { readdirSync, readFileSync } from 'fs';

// Checks if the request domain is whitelisted on allow_domain
export function domainCheck(req: IncomingMessage): boolean {
    for(const domain of allow_domain) {
        if(req.headers.host === domain)
            return true;
        if(domain.startsWith("*.")) {
            const domainName = domain.split("*")[1];
            if(req.headers.host?.endsWith(domainName))
                return true;
        }
    }
    return false;
}

export function getAllCAContent() {
    const ca_path = `${__dirname}/../allow_ca/`;
    return readdirSync(ca_path)
    .filter((cert) => cert.endsWith(".pem") || cert.endsWith(".crt") || cert.endsWith(".cer"))
    .map((cert) => readFileSync(`${ca_path}${cert}`));
}

export function setCORS(res: ServerResponse<IncomingMessage>) {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

// export function checkCAHash(req: IncomingMessage): boolean {
//     const socket = req.socket as TLSSocket;
//     const userCert = socket.getPeerCertificate(true)
//     if(!userCert)
//         return false;
    
//     console.log(userCert.issuerCertificate.fingerprint);

//     for(const ca_hash of allow_CA_sha1)
//         if(userCert.issuerCertificate.fingerprint === ca_hash)
//             return true;
//     return false;
// }

export function checkCA(req: IncomingMessage): boolean {
    const socket = req.socket as TLSSocket;
    const userCert = socket.getPeerCertificate(true)
    if(!userCert || !userCert.issuerCertificate)
        return false;
    // Disallow self-signed cause you really wouldn't need to use this anyway for that
    if(userCert.issuerCertificate.fingerprint === userCert.fingerprint)
        return false;
    return true;
}