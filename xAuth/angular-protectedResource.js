/*

The MIT License (MIT)

Copyright (C) 2013 Ryan Wells (ryaanwells@googlemail.com) and IC Mobile Lab (www.icmobilelab.com)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

/*
 * Current Prerequisites:
 * - angular.js  >1.0.7
 * - angular-cookies.js (not currently used but will be soon
 * - jquery >1.9.1 (until angularjs cookies are fully implemented
 * - CryptoJS hmac-sha1 and enc-base64.
 * - jquery.cookie.js 
 */
angular.module('protectedResource', ['ngCookies'])
  .factory('$protectedResource', function($http,$q,$cookies,$cookieStore){
    
    var accessTokenURL = "URL to validate username and password";
    var consumer_key = "Public Consumer Key";
    var consumer_secret = "Public Consumer Secret Key";
    var nonce_size = 30; //size of nonce used in auth header
    var cookieName = "authCookie"; //Cookie in which to save the access tokens for persistence
    
    
    /*
     * Percent encode a string.
     *
     * PARAMS: "" - string to be encoded.
     * RETURN: "" - percent encoded string.
     */
    function percentEncode(s){
      if (s == null) {
	return "";
      }
      s = encodeURIComponent(s);
      // encodeURIComponent ignores: - _ . ~ ! * ' ( )
      // OAuth only allows: - _ . ~
      // Source: http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Global_Functions:encodeURIComponent
      s = s.replace(/\!/g, "%21")
	.replace(/\*/g, "%2A")
	.replace(/\'/g, "%27")
	.replace(/\(/g, "%28")
	.replace(/\)/g, "%29");
      return s;
    }
    
    /*
     * Generate a pseudoRandom string from [a-zA-Z0-9]
     *
     * PARAMS: 0  - Length of the nonce
     * RETURN: "" - The nonce
     */
    function generateNonce(length){
      var out = [];
      var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
      for(var i=0; i<length; i++){
	out[i] = possible.charAt(Math.floor(Math.random()*possible.length));
      }
      return out.join("");
    }
    
    /*
     * Percent encodes an objects key/value pairs.
     * 
     * PARAMS: obj {} - an object to be encoded
     * RETURN: obj {} - a key/value percent encoded object
     */
    function encode(obj){
      var encoded = {};
      for(var k in obj){
	encoded[percentEncode(k)] = percentEncode(obj[k]);
      }
      return encoded;
    }
    
    /*
     * Lexographically orders the keys of a given object
     *
     * PARAMS: {} - an object
     * RETURN: [] - an orderd array of the KEYS of the given object
     */
    function orderKeys(obj){
      var ordered = [];
      for(var k in obj){
	ordered.push(k);
      }
      ordered.sort();
      return ordered;
    }
    
    /*
     * Creates a parameter string from an array of keys and the original
     * object used to create the array of keys. The order of the key/value
     * pairs in the parameter string is given by the order of the array of
     * keys
     *
     * PARAMS: [] - Array of keys. (Should be ordered for Auth but function does
     *                              not depend on this)
     *         {} - Original object used to create the array of keys. If a key in 
     *              the Array of keys is not found in this object then the key is
     *              still added - "...&notFoundKey=&foundKey=foundKeyVal&..."
     *
     * RETURN: "" - Parameter string.
     */
    function createParamString(orderedKeys, obj){
      if (orderedKeys.length && obj){
	var key = orderedKeys.shift();
	var output = key + "=" + obj[key];
	while(orderedKeys.length){
	  key = orderedKeys.shift();
	  output += "&" + key + "=" + obj[key];
	}
	return output
      }
      return ""
    }
    
    /*
     * Creates the base string for authorization
     *
     * PARAMS: "" - HTTP Method name. Function will capitalise.
     *         "" - Fully qualified URL.
     *         "" - Parameter string.
     * RETURN: "" - Formatted base string for use in auth operations.
     */
    function baseString(method, url, param){
      var output = method.toUpperCase() + "&";
      output+= percentEncode(url) + "&";
      output+= percentEncode(param);
      return output;
    }
    
    /*
     * Helper function for creating the base string used in authorisation operations.
     * 
     * PARAMS: "" - HTTP Method name.
     *         "" - Fully qualified url.
     *         {} - Parameters object containing all parameters to be included in signature.
     * RETURNL "" - Fully formatted base string.
     */
    function makeBaseString(method,url,params){
      var encoded = encode(params);
      orderedKeys = orderKeys(encoded);
      paramString = createParamString(orderedKeys,encoded);
      return baseString(method,url,paramString);
    }
    
    /*
     * Generates Authorization header string for requesting Access Tokens.
     *
     * PARAMS: {} - Object containing required header data. 
     *              Required Keys:
     *                 - "oauth_nonce"            OAuth Nonce
     *                 - "oauth_signature_method" OAuth signature ashing method
     *                 - "oauth_timestamp"        OAuth timestamp - same timestamp should be
     *                                                              used throughout process.
     *                 - "oauth_consumer_key"     OAuth consumer key.
     *                 - "oauth_signature"        OAuth signature hashed using "oauth_signature_method"
     *                 - "oauth_version"          OAuth version used, usually "1.0"
     *
     * RETURN: "" - Header string built from PARAMS
     */
    function makeAuthorizationHeader(obj){
      var sig = "OAuth ";
      sig +="oauth_nonce=\"" + obj["oauth_nonce"] + "\", ";
      sig +="oauth_signature_method=\"" + obj["oauth_signature_method"] + "\", ";
      sig +="oauth_timestamp=\"" + obj["oauth_timestamp"] + "\", ";
      sig +="oauth_consumer_key=\"" + obj["oauth_consumer_key"] + "\", ";
      sig +="oauth_signature=\"" + obj["oauth_signature"] + "\", ";
      sig +="oauth_version=\"" + obj["oauth_version"] + "\", ";
      sig +="x_auth_mode=\"" + obj["x_auth_mode"] + "\", ";
      sig +="x_auth_password=\"" + obj["x_auth_password"] + "\", ";
      sig +="x_auth_username=\"" + obj["x_auth_username"] + "\"";
      return sig;
    }
    
    
    /*
     * Generates header used to access protected resources.
     *
     * PARAMS: {} - Obect containing required header data.
     *              Required Keys:
     *                 - "oauth_nonce"            OAuth Nonce
     *                 - "oauth_signature_method" OAuth signature ashing method
     *                 - "oauth_timestamp"        OAuth timestamp - same timestamp should be
     *                                                              used throughout each process.
     *                 - "oauth_consumer_key"     OAuth consumer key.
     *                 - "oauth_token"            OAuth token (not secret) given after 
     *                                                                     login/access granted.
     *                 - "oauth_signature"        OAuth signature hashed using "oauth_signature_method"
     *                 - "oauth_version"          OAuth version used, usually "1.0"
     *
     * RETURN: "" - Header string built from PARAMS
     */
    function makeRequestHeader(obj){
      var sig = "OAuth ";
      sig +="oauth_nonce=\""+obj["oauth_nonce"] + "\", ";
      sig +="oauth_signature_method=\""+obj["oauth_signature_method"] + "\", ";
      sig +="oauth_timestamp=\""+obj["oauth_timestamp"] + "\", ";
      sig +="oauth_consumer_key=\""+obj["oauth_consumer_key"] + "\", ";
      sig +="oauth_token=\""+obj["oauth_token"] + "\", ";
      sig +="oauth_signature=\""+ obj["oauth_signature"] + "\", ";
      sig +="oauth_version=\""+obj["oauth_version"] +"\"";
      return sig;
    }
    
    /*
     * Extracts two keys from an access token query response string.
     *
     * PARAMS: "" - formatted result string containing OAuth/xAuth access keys
     * RETURN: {} - object with access key names as object keys
     */
    function getKeysFromString(resultString){
      var keys = {};
      var split = resultString.split("&");
      var first = split[0].split("=");
      var second = split[1].split("=");
      keys[first[0]] = first[1];
      keys[second[0]]= second[1];
      return keys;
    }
    
    /* 
     * Helper function to get the Authorization tokens from an xAuth transaction
     *
     * PARAMS: "" - Username of the current user
     *         "" - Password of the current user
     *
     * RETURN: $q - a promise for the transaction. This is a standard $http $q promise.
     */
    function getAuthTokens(username,password){
      var date = new Date();
      var time = Math.round(date.getTime()/1000).toString();
      var params = {
	"oauth_consumer_key": consumer_key,
	"oauth_nonce": generateNonce(nonce_size),
	"oauth_signature_method":"HMAC-SHA1",
	"oauth_timestamp": time,
	"oauth_version": "1.0",
	"x_auth_mode": "client_auth",
	"x_auth_password": password,
	"x_auth_username": username
      };
      var base = makeBaseString("post",accessTokenURL,params);
      var signature = percentEncode(CryptoJS
				    .HmacSHA1(base,consumer_secret+"&")
				    .toString(CryptoJS.enc.Base64));
      params["oauth_signature"] = signature;
      var authHead = makeAuthorizationHeader(params);

      var promise = $http({
	method:"POST",
	headers:{'Authorization':authHead},
	url:accessTokenURL
      });
      return promise
    }
    
    
    /*
     * Sets up and exectutes a transaction with the specified API.
     * 
     * PARAMS: {} - object of OAuth keys
     *
     * RETURN: $q - a promise for the transaction. This is a standard $http $q promise.
     */
    function interractWithAPI(config, keys){
      var date = new Date()
      var method = config.method.toUpperCase();
      var time = Math.round(date.getTime()/1000).toString();
      var start ={
	"oauth_consumer_key": consumer_key,
	"oauth_token": keys["oauth_token"],
	"oauth_nonce": generateNonce(nonce_size),
	"oauth_signature_method":"HMAC-SHA1",
	"oauth_timestamp": time,
	"oauth_version": "1.0",
      };
      var base = makeBaseString(method,config.url,start);
      var signature = percentEncode(CryptoJS
				    .HmacSHA1(base,consumer_secret+"&"+keys["oauth_token_secret"])
				    .toString(CryptoJS.enc.Base64));
      start["oauth_signature"]=signature;
      var authHead = makeRequestHeader(start);
      var httpConf = {method:method,
		      url:config.url,
		      headers:{'Authorization':authHead, 
			       'Content-Type':'application/x-www-form-urlencoded'
			      }
		     }
      if(config.data){
	httpConf["data"] = config.data;
	httpConf["headers"]["Content-Type"] = "application/json";
      }
      var promise = $http(httpConf);
      return promise;
    }
    
    // Holds OAuth keys
    var keys = {};
    
    // Array of {promise,config} objects (known as requests) pending keys.
    var waiting = [];
    // Array of {promise,config} objects (known as requests) used to try and get keys.
    var possibleKeyRequests = [];
    // Switch to only allow one request for keys at any one time.
    var requestingKeys = false;
    
    /*
     * 
     */
    function checkCookies(){
      /* Query Version */
      $.cookie.json = true;
      var cookieKeys = $.cookie(cookieName);
      /* angularjs version - doesn't yet support path so is pretty useless.*/
      /* var cookieKeys = $cookieStore.get(cookieName); */
      if(cookieKeys !== undefined && cookieKeys["oauth_token"]!==undefined 
	 && cookieKeys["oauth_token_secret"] !== undefined){
	keys=cookieKeys;
	console.log("found");
      }
      else{
	console.log("not found");
      }
    };
    checkCookies();


    // These are what are exposed to the world.
    var functions = {};
    
    /*
     * Checks if the library is able to complete a signed request
     * PARAMS: 
     * RETURN: TF - True if the last request did not fail due to auth.
     */
    functions.hasCredentials = function(){
      return (keys && keys["oauth_token"]!== undefined
	      && keys["oauth_token_secret"]!== undefined);
    }

    /*
     * Removes credentials from library and cookies.
     * PARAMS:
     * RETURN:
     */
    functions.clear = function(){
      keys = {};
      $.removeCookie(cookieName,{path:'/'});
    }

    /*
     * Generic request to API. Method, url and data are set through the config object:
     *    config:{
     *        username: "", // Username of current user. Only needed to get keys, not saved.
     *        password: "", // Password of current user. Only needed to get keys, not saved.
     *        url:      "", // API endpoint to attempt to access.
     *        method:   "", // HTTP method for "url".
     *        nokeys:   TF, // Boolean value specifying whether endpoint needs oauth keys.
     *    }
     *    Neither "username" or "password" need to be included after acquiring keys. 
     * PARAMS: {} - Config object as described above.
     * RETURN: $q - Promise for current request.
     */
    functions.execute = function(config){
      var promise = new $q.defer();
      /* While we do not have keys for this session, we do not want every request to
       * query the API to get an individual key for that request so we queue the requests
       * up waiting for the keys to be returned. FIFO queue.
       */
      if(!keys["oauth_token"] && !config.nokeys){
	/* Needs keys for request but cannot get them from this request. */
	if((!config.username || !config.password) && !config.nokeys){
	  waiting.push({"promise":promise,"config":config});
	}
	else{
	  /* This request might be able to get keys.
	   * Treat like normal request but multipurpose this promise to also get keys.
	   */
	  possibleKeyRequests.push({"promise":promise,"config":config});
	  /* Still only want one request for keys at any one time. */
	  if(!requestingKeys){
	    requestingKeys = true;
	    getAuthTokens(config.username,config.password)
	      .then(function(response){
		/* If the key request is successful */
		if(response.status===200){
		  /* This assumes that the keys come back uri encoded */
		  keys = getKeysFromString(response.data);
		  
		  /* jQuery version */
		  $.cookie.json = true;
		  $.cookie(cookieName,keys,{path:"/", expires:30});
		  /* angularjs version  - doesn't yet support path so is pretty useless*/
		  /* $cookieStore.put(cookieName,keys); */

		  while(waiting.length>0){
		    var next = waiting.shift();
		    /* Chain promises with one that can now be resolved as initially intended*/
		    next.promise.resolve(interractWithAPI(next.config,keys));
		  }
		  while(possibleKeyRequests.length>0){
		    var next = possibleKeyRequests.shift();
		    /* Chain promises with one that can now be resolved as initially intended*/
		    next.promise.resolve(interractWithAPI(next.config,keys));
		  }
		}
	      },function(response){
		/* Failure, so reject this request on the grounds of bad login details. */
		promise.reject(response.data);
		/* Reset trying status and continue trying possible logins */
		requestingKeys = false;
		if(possibleKeyRequests.length>0){
		  var next = possibleKeyRequests.shift();
		  next.promise.resolve(interractWithAPI(next.config,keys));
		}
	      });
	  }
	}
      }
      /* We have keys for this session, so attempt to access API  */
      else{
	interractWithAPI(config,keys).
	  then(
	    function(response){
	      promise.resolve(response);
	    },
	    function(response){
	      promise.reject(response);
	    });
      }
      return promise.promise;
    }
    
    return functions;
  });  
