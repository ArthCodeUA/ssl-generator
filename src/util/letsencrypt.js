import axios from "axios";
import fs from "fs";
import yesno from 'yesno';
import {b64, hex2b64, sha256} from "./crypto.js";
import {openssl} from "openssl-nodejs";
import config from "../config.js";

export class LetsEncrypt {
    directoryUrl = 'https://acme-v02.api.letsencrypt.org/directory';
    directory = {};

    account = {};
    order = {};
    authorizations = {};

    certificate;

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
            config.SIGNATURE_REQUEST_PATH,
            `${this.account.registration_protected_b64}.${this.account.registration_payload_b64}`
        );
        this.account.registration_sig = hex2b64((await openssl(
            `openssl dgst -sha256 -hex -sign account.key ${config.SIGNATURE_REQUEST_PATH}`,
            config.OPENSSL_DIR
        )).split('= ')[1]);
        await axios.post(this.directory.newAccount, {
            protected: this.account.registration_protected_b64,
            payload: this.account.registration_payload_b64,
            signature: this.account.registration_sig
        }, {
            headers: {'content-type': 'application/jose+json'}
        }).then(async (response) => {
            this.account.account_uri = response.headers['location'];
            await this.getNonce().then((nonce) => {
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
            config.SIGNATURE_REQUEST_PATH,
            `${this.account.update_protected_b64}.${this.account.update_payload_b64}`
        );
        this.account.update_sig = hex2b64((await openssl(
            `openssl dgst -sha256 -hex -sign account.key ${config.SIGNATURE_REQUEST_PATH}`,
            config.OPENSSL_DIR
        )).split('= ')[1]);
        await axios.post(this.account.account_uri, {
            protected: this.account.update_protected_b64,
            payload: this.account.update_payload_b64,
            signature: this.account.update_sig
        }, {
            headers: {'content-type': 'application/jose+json'}
        }).then(async () => {
            await this.getNonce().then((nonce) => {
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
            config.SIGNATURE_REQUEST_PATH,
            `${this.order.order_protected_b64}.${this.order.order_payload_b64}`
        );
        this.order.order_sig = hex2b64((await openssl(
            `openssl dgst -sha256 -hex -sign account.key ${config.SIGNATURE_REQUEST_PATH}`,
            config.OPENSSL_DIR
        )).split('= ')[1]);
        await axios.post(this.directory.newOrder, {
            protected: this.order.order_protected_b64,
            payload: this.order.order_payload_b64,
            signature: this.order.order_sig
        }, {
            headers: {'content-type': 'application/jose+json'}
        }).then((response) => {
            this.order.order_response = response.data;
            this.order.order_uri = response.headers['location'];
            this.order.finalize_uri = this.order.order_response.finalize;

            this.authorizations = {};

            for (let i = 0; i < this.order.order_response.authorizations.length; i++) {
                const auth_url = this.order.order_response.authorizations[i];
                this.authorizations[auth_url] = {
                    // Load authorization
                    "auth_payload_json": "",
                    "auth_payload_b64": "",
                    "auth_protected_json": undefined,
                    "auth_protected_b64": undefined,
                    "auth_sig": undefined,
                    "auth_response": undefined,

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

                    // Post-Challenge authorization check
                    "recheck_auth_payload_json": "",
                    "recheck_auth_payload_b64": "",
                    "recheck_auth_protected_json": undefined,
                    "recheck_auth_protected_b64": undefined,
                    "recheck_auth_sig": undefined,
                    "recheck_auth_response": undefined,
                };
            }
        });
    }

    async prepareChallenge(n) {
        const auth_url = this.order.order_response.authorizations[n];
        await this.getNonce().then(async (nonce) => {
            const protected_json = {
                "url": auth_url,
                "alg": this.account.alg,
                "nonce": nonce.headers['replay-nonce'],
                "kid": this.account.account_uri,
            };
            const protected_b64 = b64(JSON.stringify(protected_json));
            this.authorizations[auth_url]['auth_protected_json'] = protected_json
            this.authorizations[auth_url]['auth_protected_b64'] = protected_b64;
            fs.writeFileSync(
                config.SIGNATURE_REQUEST_PATH,
                `${this.authorizations[auth_url].auth_protected_b64}.${this.authorizations[auth_url].auth_payload_b64}`
            );
            this.authorizations[auth_url].auth_sig = hex2b64((await openssl(
                `openssl dgst -sha256 -hex -sign account.key ${config.SIGNATURE_REQUEST_PATH}`,
                config.OPENSSL_DIR
            )).split('= ')[1]);
        });
    }

    async requestChallenge(n) {
        const auth_url = this.order.order_response.authorizations[n];
        await axios.post(auth_url, {
            protected: this.authorizations[auth_url].auth_protected_b64,
            payload: this.authorizations[auth_url].auth_payload_b64,
            signature: this.authorizations[auth_url].auth_sig,
        }, {
            headers: {'content-type': 'application/jose+json'}
        }).then((response) => {
            this.authorizations[auth_url].auth_response = response.data;
            const challenges = this.authorizations[auth_url].auth_response.challenges;
            for (let i = 0; i < challenges.length; i++) {
                let challenge_dict = challenges[i];

                // HTTP challenge
                if (challenge_dict['type'] === "http-01") {
                    this.authorizations[auth_url].file_challenge_uri = challenge_dict['url'];
                    this.authorizations[auth_url].file_challenge_object = challenge_dict;
                }

                // DNS challenge
                if (challenge_dict['type'] === "dns-01") {
                    this.authorizations[auth_url].dns_challenge_uri = challenge_dict['url'];
                    this.authorizations[auth_url].dns_challenge_object = challenge_dict;
                }
            }
        });
    }

    async performChallenge(n) {
        const auth_url = this.order.order_response.authorizations[n];
        const domain = this.authorizations[auth_url].auth_response.identifier.value;
        const isDnsChallenge = await yesno({
            question: `Do you wish a DNS challenge or file challenge for ${domain}? DNS (default) / File`,
            yesValues: ['DNS'],
            noValues: ['File'],
            defaultValue: true
        });
        if (isDnsChallenge) {
            const token = this.authorizations[auth_url].dns_challenge_object.token;
            const keyAuth = `${token}.${this.account.thumbprint}`;
            const keyAuth_bytes = [];
            for (let i = 0; i < keyAuth.length; i++) {
                keyAuth_bytes.push(keyAuth.charCodeAt(i));
            }
            const hash256 = b64(sha256(new Uint8Array(keyAuth_bytes)));
            await this.askForChallengeCompletion([
                `For domain ${domain}, please go to DNS and set`,
                `TXT record _acme-challenge.${domain} to the value of`,
                `${hash256}`,
                `Then wait for couple minutes until DNS updates`
            ]);
            return 'dns';
        } else {
            const token = this.authorizations[auth_url].file_challenge_object.token;
            const keyAuth = token + "." + this.account.thumbprint;
            await this.askForChallengeCompletion([
                `For domain ${domain}, please go to website directory`,
                `create a file with following path: ${domain}/.well-known/acme-challenge/${token}`,
                `and populate this file with following text`,
                `${keyAuth}`
            ]);
            return 'file';
        }
    }

    async confirmChallenge(n, method) {
        const auth_url = this.order.order_response.authorizations[n];
        await this.getNonce().then(async (nonce) => {
            const protected_json = {
                "url": this.authorizations[auth_url].dns_challenge_object.url,
                "alg": this.account.alg,
                "nonce": nonce.headers['replay-nonce'],
                "kid": this.account.account_uri,
            };
            const protected_b64 = b64(JSON.stringify(protected_json));
            this.authorizations[auth_url][method + '_protected_json'] = protected_json
            this.authorizations[auth_url][method + '_protected_b64'] = protected_b64;
            fs.writeFileSync(
                config.SIGNATURE_REQUEST_PATH,
                `${protected_b64}.${b64('{}')}`
            );
            this.authorizations[auth_url][method + '_challenge_sig'] = hex2b64((await openssl(
                `openssl dgst -sha256 -hex -sign account.key ${config.SIGNATURE_REQUEST_PATH}`,
                config.OPENSSL_DIR
            )).split('= ')[1]);
        });
    }

    async validateChallenge(n, method) {
        const auth_url = this.order.order_response.authorizations[n];
        const challenge_url = this.authorizations[auth_url].dns_challenge_object.url;
        await axios.post(challenge_url, {
            protected: this.authorizations[auth_url][method + '_protected_b64'],
            payload: b64('{}'),
            signature: this.authorizations[auth_url][method + '_challenge_sig'],
        }, {
            headers: {'content-type': 'application/jose+json'}
        }).then(async (response) => {
            this.authorizations[auth_url][method + '_challenge_response'] = response.data;
            await this.reCheckSignature(n);
        });
    }

    async checkChallenge(n) {
        const auth_url = this.order.order_response.authorizations[n];
        await axios.post(auth_url, {
            protected: this.authorizations[auth_url].recheck_auth_protected_b64,
            payload: this.authorizations[auth_url].recheck_auth_payload_b64,
            signature: this.authorizations[auth_url].recheck_auth_sig,
        }, {
            headers: {'content-type': 'application/jose+json'}
        }).then(async (response) => {
            this.authorizations[auth_url].recheck_auth_response = response.data;
            if (response.data.status === 'pending') {
                console.log(
                    `Checked, but status still pending, recheck in ${+config.RECHECK_INTERVAL / 1000} seconds`
                );
                setTimeout(async () => {
                    await this.reCheckSignature(n);
                    await this.checkChallenge(n);
                }, +config.RECHECK_INTERVAL);
            } else if (response.data.status === 'valid') {
                console.log('Verified!');
                return true;
            } else {
                throw new Error('Failed, start one more time');
            }
        });
    }

    async reCheckSignature(n) {
        const auth_url = this.order.order_response.authorizations[n];
        await this.getNonce().then(async (nonce) => {
            const protected_json = {
                "url": auth_url,
                "alg": this.account.alg,
                "nonce": nonce.headers['replay-nonce'],
                "kid": this.account.account_uri,
            };
            const protected_b64 = b64(JSON.stringify(protected_json));
            this.authorizations[auth_url].recheck_auth_protected_json = protected_json
            this.authorizations[auth_url].recheck_auth_protected_b64 = protected_b64;
            fs.writeFileSync(
                config.SIGNATURE_REQUEST_PATH,
                `${protected_b64}.${this.authorizations[auth_url].recheck_auth_payload_b64}`
            );
            this.authorizations[auth_url].recheck_auth_sig = hex2b64((await openssl(
                `openssl dgst -sha256 -hex -sign account.key ${config.SIGNATURE_REQUEST_PATH}`,
                config.OPENSSL_DIR
            )).split('= ')[1]);
        });
    }

    askForChallengeCompletion(challenge) {
        return new Promise(async (resolve) => {
            let challengeDone = false;
            while (!challengeDone) {
                challenge.forEach((string) => console.log(string));
                challengeDone = await yesno({
                    question: "Are you done doing challenge? Y/n",
                    defaultValue: true
                });
            }
            resolve(true);
        });
    }

    async prepareFinalizeOrder() {
        await this.getNonce().then(async (nonce) => {
            this.order.finalize_protected_json = {
                "url": this.order.finalize_uri,
                "alg": this.account.alg,
                "nonce": nonce.headers['replay-nonce'],
                "kid": this.account.account_uri,
            }
            this.order.finalize_protected_b64 = b64(JSON.stringify(this.order.finalize_protected_json));
            fs.writeFileSync(
                config.SIGNATURE_REQUEST_PATH,
                `${this.order.finalize_protected_b64}.${this.order.finalize_payload_b64}`
            );
            this.order.finalize_sig = hex2b64((await openssl(
                `openssl dgst -sha256 -hex -sign account.key ${config.SIGNATURE_REQUEST_PATH}`,
                config.OPENSSL_DIR
            )).split('= ')[1]);
        });
    }

    async finalizeOrder() {
        await axios.post(this.order.finalize_uri, {
            protected: this.order.finalize_protected_b64,
            payload: this.order.finalize_payload_b64,
            signature: this.order.finalize_sig,
        }, {
            headers: {'content-type': 'application/jose+json'}
        }).then(async (response) => {
            this.order.finalize_response = response.data;
            await this.reCheckOrderSignature();
        });
    }

    async checkOrder() {
        await axios.post(this.order.order_uri, {
            protected: this.order.recheck_order_protected_b64,
            payload: this.order.recheck_order_payload_b64,
            signature: this.order.recheck_order_sig,
        }, {
            headers: {'content-type': 'application/jose+json'}
        }).then(async (response) => {
            this.order.recheck_order_response = response.data;
            if (response.data.status === 'pending' || response.data.status === 'processing' || response.data.status === 'ready') {
                console.log(
                    `Checked, but status still pending, recheck in ${+config.RECHECK_INTERVAL / 1000} seconds`
                );
                setTimeout(async () => {
                    await this.reCheckOrderSignature();
                    await this.checkOrder();
                }, +config.RECHECK_INTERVAL);
            } else if (response.data.status === 'valid') {
                this.order.cert_uri = response.data.certificate;
                await this.getNonce().then(async (nonce) => {
                    this.order.cert_protected_json = {
                        "url": this.order.cert_uri,
                        "alg": this.account.alg,
                        "nonce": nonce.headers['replay-nonce'],
                        "kid": this.account.account_uri,
                    }
                    this.order.cert_protected_b64 = b64(JSON.stringify(this.order.cert_protected_json));
                    fs.writeFileSync(
                        config.SIGNATURE_REQUEST_PATH,
                        `${this.order.cert_protected_b64}.${this.order.cert_payload_b64}`
                    );
                    this.order.cert_sig = hex2b64((await openssl(
                        `openssl dgst -sha256 -hex -sign account.key ${config.SIGNATURE_REQUEST_PATH}`,
                        config.OPENSSL_DIR
                    )).split('= ')[1]);
                });
            } else {
                throw new Error('Failed, start one more time');
            }
        });
    }

    async reCheckOrderSignature() {
        await this.getNonce().then(async (nonce) => {
            this.order.recheck_order_protected_json = {
                "url": this.order.order_uri,
                "alg": this.account.alg,
                "nonce": nonce.headers['replay-nonce'],
                "kid": this.account.account_uri,
            }
            this.order.recheck_order_protected_b64 = b64(JSON.stringify(this.order.recheck_order_protected_json));
            fs.writeFileSync(
                config.SIGNATURE_REQUEST_PATH,
                `${this.order.recheck_order_protected_b64}.${this.order.recheck_order_payload_b64}`
            );
            this.order.recheck_order_sig = hex2b64((await openssl(
                `openssl dgst -sha256 -hex -sign account.key ${config.SIGNATURE_REQUEST_PATH}`,
                config.OPENSSL_DIR
            )).split('= ')[1]);
        });
    }

    async getCertificate() {
        this.certificate = (await axios.post(this.order.cert_uri, {
            protected: this.order.cert_protected_b64,
            payload: this.order.cert_payload_b64,
            signature: this.order.cert_sig,
        }, {
            headers: {'content-type': 'application/jose+json'}
        })).data;
        return this.certificate;
    }

}