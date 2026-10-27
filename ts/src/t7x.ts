
//  ---------------------------------------------------------------------------

import ndax from './ndax.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ExchangeError, AuthenticationError } from './base/errors.js';
import type { Dict, NullableDict, Str } from './base/types.js';
//import type { Balances, Dict, NullableDict, Str } from './base/types.js';

//  ---------------------------------------------------------------------------

/**
 * @class t7x
 * @augments ndax
 * @description T7X runs on the AlphaPoint APEX platform, the same platform as NDAX, so it reuses the ndax implementation with its own endpoints
 */
export default class t7x extends ndax {
    override describe (): any {
        return this.deepExtend (super.describe (), {
            'id': 't7x',
            'name': 'T7X',
            'countries': [ 'US' ],
            'certified': false,
            'pro': true,
            'urls': {
                'logo': 'https://t7x.io/assets/images/logos/logo.png',
                'test': {
                    'public': 'https://api.t7x.apstage.net/AP',
                    'private': 'https://api.t7x.apstage.net/AP',
                },
                'api': {
                    'public': 'https://api.t7x.alphaprod.net/AP',
                    'private': 'https://api.t7x.alphaprod.net/AP',
                },
                'www': 'https://t7x.io',
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
    override async signIn (params: Dict = {}): Promise<Dict> {
        this.checkRequiredCredentials ();
        // sign () sends the APIKey, Signature, UserId and Nonce headers for this endpoint
        const response = await this.publicGetAuthenticateUser (params);
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
        const sessionToken = this.safeString2 (response, 'SessionToken', 'sessionToken');
        if (sessionToken === undefined) {
            throw new AuthenticationError (this.id + ' signIn() failed: ' + this.json (response));
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
    apiKeyAuthHeaders (): Dict {
        const nonce = this.nonce ().toString ();
        const auth = nonce + this.uid + this.apiKey;
        const signature = this.hmac (this.encode (auth), this.encode (this.secret), sha256);
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
    override sign (path: string, api: string[] = [ 'public' ], method: string = 'GET', params: Dict = {}): Dict {
        const apiName = api[0];
        let bodySigned: Str = undefined;
        let headersSigned: NullableDict = undefined;
        const apiUrl = this.safeString (this.urls['api'], apiName);
        if (apiUrl === undefined) {
            throw new ExchangeError (this.id + ' sign() has no API URL for this endpoint');
        }
        let url = apiUrl + '/' + this.implodeParams (path, params);
        let query = this.omit (params, this.extractParams (path));
        if (apiName === 'public') {
            if (path === 'AuthenticateUser') {
                this.checkRequiredCredentials ();
                headersSigned = this.apiKeyAuthHeaders ();
            } else if (path === 'Authenticate') {
                const auth = this.login + ':' + this.password;
                const auth64 = this.stringToBase64 (auth);
                headersSigned = {
                    'Authorization': 'Basic ' + auth64,
                };
            } else if (path === 'Authenticate2FA') {
                const pending2faToken = this.safeString (this.options, 'pending2faToken');
                if (pending2faToken !== undefined) {
                    headersSigned = {
                        'Pending2FaToken': pending2faToken,
                    };
                    query = this.omit (query, 'pending2faToken');
                }
            }
            if (Object.keys (query).length > 0) {
                url += '?' + this.urlencode (query);
            }
        } else if (apiName === 'private') {
            this.checkRequiredCredentials ();
            const sessionToken = this.safeString (this.options, 'sessionToken');
            if (sessionToken === undefined) {
                headersSigned = this.apiKeyAuthHeaders ();
            } else {
                headersSigned = {
                    'APToken': sessionToken,
                };
            }
            if (method === 'POST') {
                headersSigned['Content-Type'] = 'application/json';
                bodySigned = this.json (query);
            } else {
                if (Object.keys (query).length > 0) {
                    url += '?' + this.urlencode (query);
                }
            }
        }
        const headersResolved: NullableDict = headersSigned;
        const bodyResolved: Str = bodySigned;
        return { 'url': url, 'method': method, 'body': bodyResolved, 'headers': headersResolved };
    }

    //override async fetchBalance (params: Dict = {}): Promise<Balances> {
    //    // re-declared here so the Go transpile binds this.parseBalance to t7x, not ndax
    //    const omsId = this.safeInteger (this.options, 'omsId', 1);
    //    if (this.markets === undefined) {
    //        await this.loadMarkets ();
    //    }
    //    await this.loadAccounts ();
    //    const defaultAccountId = this.safeInteger2 (this.options, 'accountId', 'AccountId');
    //    let accountId = this.safeInteger2 (params, 'accountId', 'AccountId', defaultAccountId);
    //    if (accountId === undefined) {
    //        accountId = this.parseToInt (this.accounts[0]['id']);
    //    }
    //    const paramsOmitted: Dict = this.omit (params, [ 'accountId', 'AccountId' ]);
    //    const request: Dict = {
    //        'omsId': omsId,
    //        'AccountId': accountId,
    //    };
    //    const response = await this.privateGetGetAccountPositions (this.extend (request, paramsOmitted));
    //    return this.parseBalance (response);
    //}

    //override parseBalance (response: any): Balances {
    //    const result: Dict = {
    //        'info': response,
    //        'timestamp': undefined,
    //        'datetime': undefined,
    //    };
    //    for (let i = 0; i < response.length; i++) {
    //        const balance = this.safeDict (response, i);
    //        const currencyId = this.safeString (balance, 'ProductId');
    //        let code: Str = undefined;
    //        if ((currencyId !== undefined) && (this.currencies_by_id !== undefined) && (currencyId in this.currencies_by_id)) {
    //            code = this.safeCurrencyCode (currencyId);
    //        } else {
    //            // GetAccountPositions already carries the symbol; don't drop the row
    //            code = this.safeCurrencyCode (this.safeString (balance, 'ProductSymbol'));
    //        }
    //        if (code !== undefined) {
    //            const account = this.account ();
    //            account['total'] = this.safeString (balance, 'Amount');
    //            account['used'] = this.safeString (balance, 'Hold');
    //            result[code] = account;
    //        }
    //    }
    //    return this.safeBalance (result);
    //}
}
