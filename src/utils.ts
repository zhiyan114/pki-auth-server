import { IncomingMessage, ServerResponse } from 'http';
import { allow_domain, rejectNoValidCRL } from '../config.json';
import { DetailedPeerCertificate, TLSSocket } from 'tls';
import { readdirSync, readFileSync } from 'fs';
import { CertificateRevocationList, CRLDistributionPoints, Certificate } from 'pkijs';
import { getCertStatus } from 'easy-ocsp';

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

    if(!socket.authorized)
        return false;
    if(!userCert || !userCert.issuerCertificate)
        return false;
    // Disallow self-signed cause you really wouldn't need to use this anyway for that
    if(userCert.issuerCertificate.fingerprint === userCert.fingerprint)
        return false;
    return true;
}

export async function checkClientCert(req: IncomingMessage) {
    const socket = req.socket as TLSSocket;
    const userCert = socket.getPeerCertificate(true)

    // Start with expiration check
    if(Date.now() > new Date(userCert.valid_to).getTime())
        return false;

    // OCSP check first
    // @TODO: Do OCSP check and if that fails, do CRL check

    try {
        switch((await getCertStatus(userCert.raw)).status) {
            case "revoked":
                console.log(`OCSP: ${userCert.serialNumber} failed the check`)
                return false;
            case "good":
                console.log(`OCSP: ${userCert.serialNumber} passed the check`)
                return true;
        }
    } catch(ex: unknown) {
        const err = ex as Error;
        if(err.message === "Certificate does not contain OCSP url")
            return CRLCheck(userCert);
        return !rejectNoValidCRL;
    }
}

function CRLCheck(cert: DetailedPeerCertificate): boolean {
    // CRL Checks
    const distPointExists = Certificate.fromBER(cert.raw).extensions?.find((ext) => ext.extnID === "2.5.29.31");
    // You should at least have a CRL... right?
    if(!distPointExists)
        return !rejectNoValidCRL;
    const distroPoint = CRLDistributionPoints.fromBER(distPointExists?.extnValue.valueBlock.valueHexView).distributionPoints;
    
    const RevocationURI: string[] = [];
    for(const distro of distroPoint)
        if(distro.distributionPoint)
            // @ts-expect-error - Bad Type Definition
            for(const point of distro.distributionPoint)
                if(point.type === 6)
                    RevocationURI.push(point.value);
    if(RevocationURI.length === 0)
        return !rejectNoValidCRL;

    // @TODO: Fetch the CRL from the actual URL and do the checks
    return true;
}