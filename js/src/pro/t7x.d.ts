import ndax from './ndax.js';
import type { Dict } from '../base/types.js';
/**
 * @class t7x
 * @augments ndax
 * @description T7X runs on the AlphaPoint APEX platform, the same platform as NDAX, so it reuses the ndax implementation with its own endpoints
 */
export default class t7x extends ndax {
    describe(): any;
    /**
     * @method
     * @name t7x#signIn
     * @description sign in with the api key and get a session token, used by private calls that need one (e.g. withdraw)
     * @see https://alphapoint.github.io/slate/#authenticateuser
     * @param {object} [params] extra parameters specific to the exchange API endpoint
     * @returns {object} the AuthenticateUser response
     */
    signIn(params?: Dict): Promise<Dict>;
    /**
     * @ignore
     * @method
     * @name t7x#apiKeyAuthHeaders
     * @description the AlphaPoint api key authentication headers, signature = hmac-sha256 (nonce + userId + apiKey, secret)
     * @returns {object} the Nonce, APIKey, Signature and UserId headers
     */
    apiKeyAuthHeaders(): Dict;
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
    sign(path: string, api?: string[], method?: string, params?: Dict): Dict;
}
