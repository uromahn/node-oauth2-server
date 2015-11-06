/**
 * Copyright 2013-present NightWorld.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var error = require('./error'),
  is = require('type-is'),
  runner = require('./runner'),
  auth = require('basic-auth');

module.exports = Authorise;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
  extractCredentials,
  checkClient,
  getBearerToken,
  checkToken
];

/**
 * Authorise
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function Authorise (config, req, next) {
  this.config = config;
  this.model = config.model;
  this.req = req;

  runner(fns, this, next);
}

/**
 * Basic request validation and extraction of grant_type and client creds
 *
 * @param  {Function} done
 * @this   OAuth
 */
function extractCredentials (done) {
  // Only POST is acceptable
  if (this.req.method !== 'POST') {
    return done(error('invalid_request', 'Method must be POST'));
  }

  var contentType = this.req.headers['content-type'];
  var type = is.is(contentType, this.config.acceptedContentType);
  var vre = this.config.regex.vre;
  var version = vre.exec(contentType);

  if (!type) {
    return done(error('invalid_request',
      'Only content type of "' + this.config.acceptedContentType.join('" or "') + '" encoding are allowed'));
  }

  if (!version) {
    return done(error('invalid_version', 'Invalid API version: expected "' + this.config.apiVersion + '"'));
  }

  // Extract credentials
  // http://tools.ietf.org/html/rfc6749#section-3.2.1
  this.client = credsFromBasic(this.req) || credsFromBody(this.req) || credsFromHeader(this.req);
  if (!this.client.clientId ||
      !this.client.clientId.match(this.config.regex.clientId)) {
    return done(error('invalid_client',
      'Invalid or missing client_id parameter'));
  } else if (!this.client.clientSecret) {
    return done(error('invalid_client', 'Missing client_secret parameter'));
  }

  done();
}

/**
 * Client Object (internal use only)
 *
 * @param {String} id     client_id
 * @param {String} secret client_secret
 */
function Client (id, secret) {
  this.clientId = id;
  this.clientSecret = secret;
}

/**
 * Extract client creds from Basic auth
 *
 * @return {Object} Client
 */
function credsFromBasic (req) {
  var user = auth(req);
  console.log('In credsFromBasic: user=', user);

  if (!user) return false;

  return new Client(user.name, user.pass);
}

/**
 * Extract client creds from body
 *
 * @return {Object} Client
 */
function credsFromBody (req) {
  console.log('In credsFromBody: (user, password)=', req.body.client_id, req.body.client_secret);

  if (!req.body.client_id) return false;
  return new Client(req.body.client_id, req.body.client_secret);
}

/**
 * Extract client creds from header
 *
 * @return {Object} Client
 */
function credsFromHeader (req) {
  var client = req.get('x-client-id');
  var secret = req.get('x-client-secret');
  console.log('In credsFromHeader: (client, secret)=', client, secret);

  if (!client) return false;

  return new Client(client, secret);
}

/**
 * Check extracted client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkClient (done) {
  var self = this;
  this.model.getClient(this.client.clientId, this.client.clientSecret,
      function (err, client) {
    if (err) return done(error('server_error', false, err));

    if (!client) {
      return done(error('invalid_client', 'Client credentials are invalid'));
    }

    // Expose validated client
    self.req.oauth = { client: client };

    done();
  });
}

/**
 * Get bearer token
 *
 * Extract token from request according to RFC6750
 *
 * @param  {Function} done
 * @this   OAuth
 */
function getBearerToken (done) {
  var headerToken = this.req.get('Authorization'),
    getToken =  this.req.query.access_token,
    postToken = this.req.body ? this.req.body.access_token : undefined;

  // Check exactly one method was used
  var methodsUsed = (headerToken !== undefined) + (getToken !== undefined) +
    (postToken !== undefined);

  if (methodsUsed > 1) {
    return done(error('invalid_request',
      'Only one method may be used to authenticate at a time (Auth header,  ' +
        'GET or POST).'));
  } else if (methodsUsed === 0) {
    return done(error('invalid_request', 'The access token was not found'));
  }

  // Header: http://tools.ietf.org/html/rfc6750#section-2.1
  if (headerToken) {
    var matches = headerToken.match(/Bearer\s(\S+)/);

    if (!matches) {
      return done(error('invalid_request', 'Malformed auth header'));
    }

    headerToken = matches[1];
  }

  // POST: http://tools.ietf.org/html/rfc6750#section-2.2
  if (postToken) {
    if (this.req.method === 'GET') {
      return done(error('invalid_request',
        'Method cannot be GET When putting the token in the body.'));
    }

    if (!this.req.is('application/x-www-form-urlencoded') && !this.req.is('application/json')) {
      return done(error('invalid_request', 'When putting the token in the ' +
        'body, content type must be application/x-www-form-urlencoded or application/json.'));
    }
  }

  this.bearerToken = headerToken || postToken || getToken;
  done();
}

/**
 * Check token
 *
 * Check it against model, ensure it's not expired
 * @param  {Function} done
 * @this   OAuth
 */
function checkToken (done) {
  var self = this;
  this.model.getAccessToken(this.bearerToken, function (err, token) {
    if (err) return done(error('server_error', false, err));

    if (!token) {
      return done(error('invalid_token',
        'The access token provided is invalid.'));
    }

    if (token.expires !== null &&
      (!token.expires || token.expires < new Date())) {
      return done(error('invalid_token',
        'The access token provided has expired.'));
    }

    // Expose params
    self.req.oauth = { bearerToken: token };
    self.req.user = token.user ? token.user : { id: token.userId };

    done();
  });
}
