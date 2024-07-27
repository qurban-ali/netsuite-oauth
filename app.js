'use strict';

// Dependencies
const request = require('request');
const OAuth   = require('oauth-1.0a');
const crypto  = require('crypto');

module.exports = NetSuiteOAuth;

/**
 * Constructor
 *
 * @param url
 * @param method
 * @param consumerKey
 * @param consumerSecret
 * @param tokenId
 * @param tokenSecret
 * @param account
 * @param offset
 * 
 * @returns {PromiseLike<ArrayBuffer>}
 * @constructor
 */
function NetSuiteOAuth(url, method, consumerKey, consumerSecret, tokenId, tokenSecret, account, offset = 0) {
    this.oauth = OAuth({
        consumer: {
            key: consumerKey,
            secret: consumerSecret
        },
        realm: account,
        signature_method: 'HMAC-SHA256',
        hash_function(base_string, key) {
            return crypto.createHmac('sha256', key).update(base_string).digest('base64');
        }
    });

    this.request_data = {
        url: `${url}?limit=1000&offset=${offset}`,
        method: method
    };

    this.token = {
        key: tokenId,
        secret: tokenSecret
    };

    this.headers = this.oauth.toHeader(this.oauth.authorize(this.request_data, this.token));
    this.headers['Content-Type'] = 'application/json';
    this.headers['Prefer'] = 'transient';
}

NetSuiteOAuth.prototype.get = function() {
    return new Promise((resolve, reject) => {
        request({
            url: this.request_data.url,
            method: this.request_data.method,
            headers: this.headers
        }, function(error, response, body) {
            if (error || response.statusCode.toString()[0] != 2) {
                console.log('Body data:', body);
                reject(body || error);
            }
            else {
                if (typeof body == 'string') body = JSON.parse(body);
                resolve(body || error);
            }
        });

    });
};

NetSuiteOAuth.prototype.post = function(data) {
    return new Promise((resolve, reject) => {
        request({
            url: this.request_data.url,
            method: this.request_data.method,
            json: data,
            headers: this.headers
        }, function(error, response, body) {
            if (error || response.statusCode.toString()[0] != 2) {
                console.log('Body data:', body);
                reject(body || error);
            }
            else {
                if (typeof body == 'string') body = JSON.parse(body);
                resolve(body || error);
            }
        });

    });
};

NetSuiteOAuth.prototype.put = function(data) {
    return new Promise((resolve, reject) => {
        request({
            url: this.request_data.url,
            method: this.request_data.method,
            json: data,
            headers: this.headers
        }, function(error, response, body) {
            if (error || response.statusCode.toString()[0] != 2) {
                console.log('Body data:', body);
                reject(body || error);
            }
            else {
                if (typeof body == 'string') body = JSON.parse(body);
                resolve(body || error);
            }
        });

    });
};
