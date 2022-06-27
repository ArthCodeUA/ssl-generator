import {openssl} from 'openssl-nodejs';
import {LetsEncrypt} from "./util/letsencrypt.js";
import {createPublicKey} from 'crypto';
import {b64, clearB64, sha256} from "./util/crypto.js";
import * as fs from 'fs';
import dotenv from 'dotenv';

dotenv.config();

export async function getCertificate(email, domains) {
    domains = domains ? domains.split(',') : [];
    if (email && domains && domains.length > 0) {
        const letsEncrypt = new LetsEncrypt();
        await letsEncrypt.populateDirectory();
        letsEncrypt.account = await populateAccount(email);
        const csr = await generateCsr(domains);
        letsEncrypt.order = populateOrder(csr, domains);
        await letsEncrypt.populateRegistrationSignature();
        await letsEncrypt.registerAccount();
        await letsEncrypt.updateAccount();
        await letsEncrypt.createNewOrder();
        for (let i = 0; i < domains.length; i++) {
            await letsEncrypt.prepareChallenge(i);
            await letsEncrypt.requestChallenge(i);
            const method = await letsEncrypt.performChallenge(i);
            await letsEncrypt.confirmChallenge(i, method);
            await letsEncrypt.validateChallenge(i, method);
            await letsEncrypt.checkChallenge(i);
        }
        await letsEncrypt.prepareFinalizeOrder();
        await letsEncrypt.finalizeOrder();
        await letsEncrypt.checkOrder();
        const certificate = await letsEncrypt.getCertificate();
        console.log(certificate);
    } else {
        console.log('Email and/or domains parameters are wrong or does not exist!');
    }
}

async function initAccountKey() {
    if (!fs.existsSync(process.env.PRIVATE_ACCOUNT_KEY_PATH)) {
        fs.mkdirSync(process.env.OPENSSL_DIR);
        const privateKey = await openssl('openssl genrsa 4096', process.env.OPENSSL_DIR);
        fs.writeFileSync(process.env.PRIVATE_ACCOUNT_KEY_PATH, String(privateKey));
    }

    return String(await openssl('openssl rsa -in account.key -pubout', process.env.OPENSSL_DIR));
}

async function populateAccount(email) {
    const publicKey = await initAccountKey();
    const jwk = createPublicKey(publicKey).export({format: 'jwk'});
    const registration_payload = {"termsOfServiceAgreed": true};
    const account_payload = {"contact": ["mailto:" + email]};
    return {
        "pubkey": publicKey,
        "alg": "RS256",
        "jwk": jwk,
        "thumbprint": await getKeyThumbprint(jwk),
        "account_uri": undefined,

        "registration_payload_json": registration_payload,
        "registration_payload_b64": b64(JSON.stringify(registration_payload)),
        "registration_protected_json": undefined,
        "registration_protected_b64": undefined,
        "registration_sig": undefined,
        "registration_response": undefined,

        "update_payload_json": account_payload,
        "update_payload_b64": b64(JSON.stringify(account_payload)),
        "update_protected_json": undefined,
        "update_protected_b64": undefined,
        "update_sig": undefined,
        "update_response": undefined,
    };
}

async function generateCsr(domains) {
    const privateKey = await openssl('openssl genrsa 4096', process.env.OPENSSL_DIR);
    let config = fs.readFileSync('/etc/ssl/openssl.cnf').toString();
    config += `\n[ SAN ]\nsubjectAltName=${domains.map(domain => `DNS:${domain}`).join(',')}`;
    fs.writeFileSync(process.env.OPENSSL_CNF_PATH, config);
    fs.writeFileSync(process.env.PRIVATE_DOMAIN_KEY_PATH, String(privateKey));
    return await openssl(
        `openssl req -new -sha256 -key domain.key -subj / -reqexts SAN -config ${process.env.OPENSSL_CNF_PATH}`,
        process.env.OPENSSL_DIR
    );
}

async function getKeyThumbprint(jwk) {
    const jwk_bytes = [];
    const jwk_string = JSON.stringify({e: jwk.e, kty: jwk.kty, n: jwk.n});
    jwk_string.split('').forEach((c, i) => {
        jwk_bytes.push(jwk_string.charCodeAt(i));
    });
    return b64(sha256(new Uint8Array(jwk_bytes)));
}

function populateOrder(csr, domains) {
    const csrMask = /-----BEGIN CERTIFICATE REQUEST-----([A-Za-z0-9+\/=\s]+)-----END CERTIFICATE REQUEST-----/;
    const csr_der = clearB64(csrMask.exec(csr)[1]);
    const finalize_payload = {"csr": csr_der};
    const order_payload = {"identifiers": []};

    for (let i = 0; i < domains.length; i++) {
        order_payload['identifiers'].push({"type": "dns", "value": domains[i]});
    }

    return {
        "csr_pem": csr,
        "csr_der": csr_der,

        "order_payload_json": order_payload,
        "order_payload_b64": b64(JSON.stringify(order_payload)),
        "order_protected_json": undefined,
        "order_protected_b64": undefined,
        "order_sig": undefined,
        "order_response": undefined,
        "order_uri": undefined,

        "finalize_uri": undefined,
        "finalize_payload_json": finalize_payload,
        "finalize_payload_b64": b64(JSON.stringify(finalize_payload)),
        "finalize_protected_json": undefined,
        "finalize_protected_b64": undefined,
        "finalize_sig": undefined,
        "finalize_response": undefined,

        "recheck_order_payload_json": "",
        "recheck_order_payload_b64": "",
        "recheck_order_protected_json": undefined,
        "recheck_order_protected_b64": undefined,
        "recheck_order_sig": undefined,
        "recheck_order_response": undefined,

        "cert_payload_json": "",
        "cert_payload_b64": "",
        "cert_protected_json": undefined,
        "cert_protected_b64": undefined,
        "cert_sig": undefined,
        "cert_response": undefined,
        "cert_uri": undefined,
    };
}

await getCertificate(process.argv[2], process.argv[3]);