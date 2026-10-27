'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var ndax = require('./ndax.js');
var sha2_js = require('@noble/hashes/sha2.js');
var errors = require('../base/errors.js');

// ----------------------------------------------------------------------------
//import type { Balances, Dict, NullableDict, Str } from '../base/types.js';
//  ---------------------------------------------------------------------------
/**
 * @class t7x
 * @augments ndax
 * @description T7X runs on the AlphaPoint APEX platform, the same platform as NDAX, so it reuses the ndax implementation with its own endpoints
 */
class t7x extends ndax["default"] {
    describe() {
        // super.describe () is the ndax rest + ndax ws description, so the T7X REST values from ../t7x.ts are repeated here as well
        return this.deepExtend(super.describe(), {
            'id': 't7x',
            'name': 'T7X',
            'countries': ['US'],
            'certified': false,
            'pro': true,
            'urls': {
                'logo': 'https://t7x.io/assets/images/logos/logo.png',
                'test': {
                    'public': 'https://api.t7x.apstage.net/AP',
                    'private': 'https://api.t7x.apstage.net/AP',
                    'ws': 'wss://api.t7x.apstage.net/WSGateway',
                },
                'api': {
                    'public': 'https://api.t7x.alphaprod.net/AP',
                    'private': 'https://api.t7x.alphaprod.net/AP',
                    'ws': 'wss://api.t7x.alphaprod.net/WSGateway',
                },
                'www': undefined,
                'doc': [
                    'https://alphapoint.github.io/slate/',
                ],
                'fees': undefined,
                'referral': undefined,
            },
            'options': {
                'omsId': 1,
            },
            'requiredCredentials': {
                'apiKey': true,
                'secret': true,
                'uid': true,
                'login': false,
                'password': false,
            },
        });
    }
    /**
     * @method
     * @name t7x#signIn
     * @description sign in with the api key and get a session token, used by private calls that need one (e.g. withdraw)
     * @see https://alphapoint.github.io/slate/#authenticateuser
     * @param {object} [params] extra parameters specific to the exchange API endpoint
     * @returns {object} the AuthenticateUser response
     */
    async signIn(params = {}) {
        this.checkRequiredCredentials();
        // sign () sends the APIKey, Signature, UserId and Nonce headers for this endpoint
        const response = await this.publicGetAuthenticateUser(params);
        //
        //     {
        //         "Authenticated": true,
        //         "SessionToken": "4a2a5857-c4e5-4fac-b09e-2c4c30b591a0",
        //         "User": { "UserId": 96, "UserName": "", "AccountId": 0, "OMSId": 1, "Use2FA": false },
        //         "Locked": false,
        //         "Requires2FA": false,
        //         "errormsg": ""
        //     }
        //
        const sessionToken = this.safeString2(response, 'SessionToken', 'sessionToken');
        if (sessionToken === undefined) {
            throw new errors.AuthenticationError(this.id + ' signIn() failed: ' + this.json(response));
        }
        this.options['sessionToken'] = sessionToken;
        return response;
    }
    /**
     * @ignore
     * @method
     * @name t7x#apiKeyAuthHeaders
     * @description the AlphaPoint api key authentication headers, signature = hmac-sha256 (nonce + userId + apiKey, secret)
     * @returns {object} the Nonce, APIKey, Signature and UserId headers
     */
    apiKeyAuthHeaders() {
        const nonce = this.nonce().toString();
        const auth = nonce + this.uid + this.apiKey;
        const signature = this.hmac(this.encode(auth), this.encode(this.secret), sha2_js.sha256);
        return {
            'Nonce': nonce,
            'APIKey': this.apiKey,
            'Signature': signature,
            'UserId': this.uid,
        };
    }
    /**
     * @method
     * @name t7x#sign
     * @description T7X request signing, replaces the inherited ndax#sign
     * @param {string} path - the endpoint path
     * @param {string[]} api - the api name, ['public'] or ['private']
     * @param {string} method - the HTTP method
     * @param {Dict} params - the request params
     * @returns { Dict } the signed authentication request headers
     * starts as a copy of ndax#sign, change it to match T7X's authentication
     */
    sign(path, api = ['public'], method = 'GET', params = {}) {
        const apiName = api[0];
        let bodySigned = undefined;
        let headersSigned = undefined;
        const apiUrl = this.safeString(this.urls['api'], apiName);
        if (apiUrl === undefined) {
            throw new errors.ExchangeError(this.id + ' sign() has no API URL for this endpoint');
        }
        let url = apiUrl + '/' + this.implodeParams(path, params);
        let query = this.omit(params, this.extractParams(path));
        if (apiName === 'public') {
            if (path === 'AuthenticateUser') {
                this.checkRequiredCredentials();
                headersSigned = this.apiKeyAuthHeaders();
            }
            else if (path === 'Authenticate') {
                const auth = this.login + ':' + this.password;
                const auth64 = this.stringToBase64(auth);
                headersSigned = {
                    'Authorization': 'Basic ' + auth64,
                };
            }
            else if (path === 'Authenticate2FA') {
                const pending2faToken = this.safeString(this.options, 'pending2faToken');
                if (pending2faToken !== undefined) {
                    headersSigned = {
                        'Pending2FaToken': pending2faToken,
                    };
                    query = this.omit(query, 'pending2faToken');
                }
            }
            if (Object.keys(query).length > 0) {
                url += '?' + this.urlencode(query);
            }
        }
        else if (apiName === 'private') {
            this.checkRequiredCredentials();
            const sessionToken = this.safeString(this.options, 'sessionToken');
            if (sessionToken === undefined) {
                headersSigned = this.apiKeyAuthHeaders();
            }
            else {
                headersSigned = {
                    'APToken': sessionToken,
                };
            }
            if (method === 'POST') {
                headersSigned['Content-Type'] = 'application/json';
                bodySigned = this.json(query);
            }
            else {
                if (Object.keys(query).length > 0) {
                    url += '?' + this.urlencode(query);
                }
            }
        }
        const headersResolved = headersSigned;
        const bodyResolved = bodySigned;
        return { 'url': url, 'method': method, 'body': bodyResolved, 'headers': headersResolved };
    }
}

exports["default"] = t7x;
