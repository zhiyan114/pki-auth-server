import { DetailedPeerCertificate } from 'tls';
import { existsSync, mkdirSync } from 'fs';
import { CertificateRevocationList, CRLDistributionPoints, Certificate } from 'pkijs';
import { rejectNoValidCRL } from '../config.json';
import { createHash } from 'crypto';

export async function CRLCheck(cert: DetailedPeerCertificate): Promise<boolean> {
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
                if(point.value.startsWith("http") || point.value.startsWith("https")) // We don't support LDAP based revocation
                    RevocationURI.push(point.value);
    if(RevocationURI.length === 0)
        return !rejectNoValidCRL;

    // Fetch the CRL
    for(const uri of RevocationURI) {
        const curlData = await PullCRLData(uri);
        // @TODO: Check the CRL Data itself
    }

    return true;
}

// CRLCheck helper function that manages fetching and caching CRL files.
const CRLCacheFolder = `${__dirname}/temp/`;
async function PullCRLData(uri: string): Promise<CertificateRevocationList> {
    // Create a temp folder to store crls
    if(!existsSync(CRLCacheFolder))
        mkdirSync(CRLCacheFolder);

    // SHA1 hash the URI to get a unique filename
    const crlName = `${createHash("sha1").update(uri+"_CRLDATA").digest("hex").slice(0, 16)}.crl`;

    // Check the cache

    const crlPull = await fetch(uri);
    if(!crlPull.ok)
        return;
    const crlData = await crlPull.arrayBuffer();
    return CertificateRevocationList.fromBER(crlData);
}

/*
Design IDEA:
 1. Check if the crl file exist in the temp cache folder.
 2. If it exists, check if it expired.
 3. If yes, fetch a new CRL and use that as the check
 4. If no, use the existing CRL file for the check.
 5. If there isnt a cache crl file, fetch a new CRL and use that as the check.
*/