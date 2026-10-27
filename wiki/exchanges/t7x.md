
<a name="t7x" id="t7x"></a>

## t7x{docsify-ignore}
**Kind**: global class  
**Extends**: <code>ndax</code>  

* [signIn](#signin)
* [sign](#sign)

<a name="t7x" id="t7x"></a>

### t7x{docsify-ignore}
T7X runs on the AlphaPoint APEX platform, the same platform as NDAX, so it reuses the ndax implementation with its own endpoints



```javascript
t7x.t7x ()
```


<a name="signIn" id="signin"></a>

### signIn{docsify-ignore}
sign in with the api key and get a session token, used by private calls that need one (e.g. withdraw)

**Kind**: instance method of [<code>t7x</code>](#t7x)  
**Returns**: <code>object</code> - the AuthenticateUser response

**See**: https://alphapoint.github.io/slate/#authenticateuser  

| Param | Type | Required | Description |
| --- | --- | --- | --- |
| params | <code>object</code> | No | extra parameters specific to the exchange API endpoint |


```javascript
t7x.signIn (params?)
```


<a name="sign" id="sign"></a>

### sign{docsify-ignore}
T7X request signing, replaces the inherited ndax#sign

**Kind**: instance method of [<code>t7x</code>](#t7x)  
**Returns**: <code>Dict</code> - the signed authentication request headers
starts as a copy of ndax#sign, change it to match T7X's authentication


| Param | Type | Description |
| --- | --- | --- |
| path | <code>string</code> | the endpoint path |
| api | <code>Array&lt;string&gt;</code> | the api name, ['public'] or ['private'] |
| method | <code>string</code> | the HTTP method |
| params | <code>Dict</code> | the request params |


```javascript
t7x.sign (path, api, method, params)
```

