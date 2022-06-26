import axios from "axios";
import {b64, hex2b64} from "./crypto.js";
import fs from "fs";
import {openssl} from "openssl-nodejs";

export class LetsEncrypt {
    directoryUrl = 'https://acme-v02.api.letsencrypt.org/directory';
    directory = {};

    account = {};
    order = {};
    authorizations = {};

    getNonce() {
        return axios.get(this.directory.newNonce);
    }

    async populateDirectory() {
        this.directory = (await axios.get(this.directoryUrl)).data;
    }

    async populateRegistrationSignature() {
        return this.getNonce().then((nonce) => {
            this.account.registration_protected_json = {
                "url": this.directory.newAccount,
                "alg": this.account.alg,
                "nonce": nonce.headers['replay-nonce'],
                "jwk": this.account.jwk,
            }
            this.account.registration_protected_b64 = b64(
                JSON.stringify(this.account.registration_protected_json)
            );
        });
    }

    async registerAccount() {
        fs.writeFileSync(
            process.env.SIGNATURE_REQUEST_PATH,
            `${this.account.registration_protected_b64}.${this.account.registration_payload_b64}`
        );
        this.account.registration_sig = hex2b64((await openssl(
            `openssl dgst -sha256 -hex -sign account.key ${process.env.SIGNATURE_REQUEST_PATH}`,
            process.env.OPENSSL_DIR
        )).split('= ')[1]);
        return await axios.post(this.directory.newAccount, {
            protected: this.account.registration_protected_b64,
            payload: this.account.registration_payload_b64,
            signature: this.account.registration_sig
        }).then((response) => {
            this.account.account_uri = response.headers['location'];
            this.getNonce().then((nonce) => {
                this.account.update_protected_json = {
                    "url": this.account.account_uri,
                    "alg": this.account.alg,
                    "nonce": nonce.headers['replay-nonce'],
                    "kid": this.account.account_uri,
                }
                this.account.update_protected_b64 = b64(JSON.stringify(this.account.update_protected_json));
            });
        });
    }

    async updateAccount() {
        fs.writeFileSync(
            process.env.SIGNATURE_REQUEST_PATH,
            `${letsEncrypt.account.update_protected_b64}.${letsEncrypt.account.update_payload_b64}`
        );
        letsEncrypt.account.update_sig = hex2b64((await openssl(
            `openssl dgst -sha256 -hex -sign account.key ${process.env.SIGNATURE_REQUEST_PATH}`,
            process.env.OPENSSL_DIR
        )).split('= ')[1]);
        return await axios.post(this.account.account_uri, {
            protected: this.account.update_protected_b64,
            payload: this.account.update_payload_b64,
            signature: this.account.update_sig
        }).then(() => {
            this.getNonce().then((nonce) => {
                this.order.order_protected_json = {
                    "url": this.directory.newOrder,
                    "alg": this.account.alg,
                    "nonce": nonce.headers['replay-nonce'],
                    "kid": this.account.account_uri,
                }
                this.order.order_protected_b64 = b64(JSON.stringify(this.order.order_protected_json));
            });
        });
    }

    async createNewOrder() {
        fs.writeFileSync(
            process.env.SIGNATURE_REQUEST_PATH,
            `${letsEncrypt.order.order_protected_b64}.${letsEncrypt.order.order_payload_b64}`
        );
        letsEncrypt.order.order_sig = hex2b64((await openssl(
            `openssl dgst -sha256 -hex -sign account.key ${process.env.SIGNATURE_REQUEST_PATH}`,
            process.env.OPENSSL_DIR
        )).split('= ')[1]);
        return await axios.post(this.directory.newOrder, {
            protected: this.order.order_protected_b64,
            payload: this.order.order_payload_b64,
            signature: this.order.order_sig
        }).then((response) => {
            this.order.order_response = response.data;
            this.order.order_uri = response.headers['location'];
            this.order.finalize_uri = this.order.order_response.finalize;

            this.authorizations = {};

            for(let i = 0; i < this.order.order_response.authorizations.length; i++) {
                const auth_url = this.order.order_response.authorizations[i];
                this.authorizations[auth_url] = {
                    // File-based HTTP challenge
                    "file_challenge_uri": undefined,
                    "file_challenge_object": undefined,
                    "file_challenge_protected_json": undefined,
                    "file_challenge_protected_b64": undefined,
                    "file_challenge_sig": undefined,
                    "file_challenge_response": undefined,

                    // DNS challenge
                    "dns_challenge_uri": undefined,
                    "dns_challenge_object": undefined,
                    "dns_challenge_protected_json": undefined,
                    "dns_challenge_protected_b64": undefined,
                    "dns_challenge_sig": undefined,
                    "dns_challenge_response": undefined,
                };
            }
        });
    }
}