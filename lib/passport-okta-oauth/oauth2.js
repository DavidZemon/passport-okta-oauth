/**
 * Module dependencies.
 */
const util = require("util");
const uid = require("uid2");
const querystring = require("querystring");
const OAuth2Strategy = require("passport-oauth").OAuth2Strategy;
const InternalOAuthError = require("passport-oauth").InternalOAuthError;

/**
 * @param {object | undefined} options
 * @param {string} options.audience audience is the Okta Domain, e.g. `https://example.okta.com`, `https://example.oktapreview.com`
 * @param {string} options.clientID clientID is the public Okta Application Client Credentials, it's a 20 character alphanumeric string e.g. `U7VYvsaiuqlDOHjIVTIA`  (generated example)
 * @param {string | undefined} options.idp idp is the Identity Provider (id). This is an optional field. it's a 20 character alphanumeric string, e.g. `qOp8aaJmCEhvep5Il6ZJ`  (generated example)
 * @param {string} options.callbackURL  callbackURL is the redirect URL Okta should return the user to. This is a URL on your server
 * @param {string[] | undefined} options.scope Optional array of scopes
 * @param {'code'} options.response_type Set this to 'code'
 * @param {function} verify
 * @constructor
 */
function Strategy(options, verify) {
  const configuredOptions = {
    ...options,
    authorizationURL: options.audience + "/oauth2/v1/authorize",
    tokenURL: options.audience + "/oauth2/v1/token",
    userInfoUrl: options.audience + "/oauth2/v1/userinfo",
  };

  OAuth2Strategy.call(this, configuredOptions, verify);

  this.name = "tsokta";
  this._userInfoUrl = configuredOptions.userInfoUrl;
  this._idp = configuredOptions.idp;
  this._state = configuredOptions.state;

  // Authorize Request using Authorization Header
  this._oauth2.getOAuthAccessToken = function (code, params, callback) {
    params = params || {};
    const codeParam =
      params.grant_type === "refresh_token" ? "refresh_token" : "code";
    params[codeParam] = code;
    const post_data = querystring.stringify(params);
    const post_headers = {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization:
        "Basic: " +
        new Buffer(this._clientId + ":" + this._clientSecret).toString(
          "base64"
        ),
    };
    this._request(
      "POST",
      this._getAccessTokenUrl(),
      post_headers,
      post_data,
      null,
      function (error, data, response) {
        if (error) callback(error);
        else {
          let results;
          try {
            // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
            // responses should be in JSON
            results = JSON.parse(data);
          } catch (e) {
            // .... However both Facebook + Github currently use rev05 of the spec
            // and neither seem to specify a content-type correctly in their response headers :(
            // clients of these services will suffer a *minor* performance cost of the exception
            // being thrown
            results = querystring.parse(data);
          }
          const access_token = results["access_token"];
          const refresh_token = results["refresh_token"];
          delete results["refresh_token"];
          callback(null, access_token, refresh_token, results); // callback results =-=
        }
      }
    );
  };
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Okta.
 * Further references at http://developer.okta.com/docs/api/resources/oidc.html#get-user-information
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `okta`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */

Strategy.prototype.userProfile = function (accessToken, done) {
  const post_headers = { Authorization: "Bearer " + accessToken };

  this._oauth2._request(
    "POST",
    this._userInfoUrl,
    post_headers,
    "",
    null,
    function (err, body, res) {
      if (err) {
        return done(
          new InternalOAuthError("failed to fetch user profile", err)
        );
      }

      try {
        const json = JSON.parse(body);
        done(null, {
          provider: "tsokta",
          id: json.sub,
          displayName: json.name,
          username: json.preferred_username,
          name: {
            fullName: json.name,
            familyName: json.family_name,
            givenName: json.given_name,
          },
          emails: [{ value: json.email }],
          _raw: body,
          _json: json,
        });
      } catch (e) {
        done(e);
      }
    }
  );
};

/**
 * Return extra Okta-specific parameters to be included in the authorization
 * request.
 *
 * @param {Object} option
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function (option) {
  const params = {};
  if (this._state) {
    params.state = true;
    params.nonce = uid(24);
  }
  if (this._idp) {
    params.idp = this._idp;
  }
  return params;
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
