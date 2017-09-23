var jwt = require("jsonwebtoken");
var UnauthorizedError = require("./errors/UnauthorizedError");
var unless = require("express-unless");
var async = require("async");
var set = require("lodash.set");
var AuthPolicy = require("./AuthPolicy");

var DEFAULT_REVOKED_FUNCTION = function(_, __, cb) {
  return cb(null, false);
};

function isFunction(object) {
  return Object.prototype.toString.call(object) === "[object Function]";
}

function wrapStaticSecretInCallback(secret) {
  return function(_, __, cb) {
    return cb(null, secret);
  };
}

module.exports = function(options) {
  if (!options || !options.secret) throw new Error("secret should be set");

  var secretCallback = options.secret;
  let extractPrincipalId = options.extractPrincipalId || (x => x);
  if (typeof extractPrincipalId === "string") {
    const key = extractPrincipalId;
    extractPrincipalId = x => x[key];
  }

  if (!isFunction(secretCallback)) {
    secretCallback = wrapStaticSecretInCallback(secretCallback);
  }

  var isRevokedCallback = options.isRevoked || DEFAULT_REVOKED_FUNCTION;

  var middleware = function(event, context, next) {
    var token;

    if (options.getToken && typeof options.getToken === "function") {
      try {
        token = options.getToken(event);
      } catch (e) {
        return next(e);
      }
    } else if (event.type === "TOKEN" || event.type === "REQUEST") {
      const inputToken =
        event.type === "REQUEST"
          ? (event.headers || {}).authorization
          : event.authorizationToken;

      var parts = (inputToken || "").split(" ");
      if (parts.length === 2) {
        var scheme = parts[0];
        var credentials = parts[1];

        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        } else {
          return next(
            new UnauthorizedError("credentials_bad_scheme", {
              message: "Format is Authorization: Bearer [token]"
            })
          );
        }
      } else if (inputToken) {
        return next(
          new UnauthorizedError("credentials_bad_format", {
            message: "Format is Authorization: Bearer [token]"
          })
        );
      }
    }

    if (!token) {
      return next(
        new UnauthorizedError("credentials_required", {
          message: "No authorization token was found"
        })
      );
    }

    var dtoken;

    try {
      dtoken = jwt.decode(token, { complete: true }) || {};
    } catch (err) {
      return next(new UnauthorizedError("invalid_token", err));
    }

    async.waterfall(
      [
        function getSecret(callback) {
          var arity = secretCallback.length;
          if (arity == 4) {
            secretCallback({}, dtoken.header, dtoken.payload, callback);
          } else {
            // arity == 3
            secretCallback({}, dtoken.payload, callback);
          }
        },
        function verifyToken(secret, callback) {
          jwt.verify(token, secret, options, function(err, decoded) {
            if (err) {
              callback(new UnauthorizedError("invalid_token", err));
            } else {
              callback(null, decoded);
            }
          });
        },
        function checkRevoked(decoded, callback) {
          isRevokedCallback({}, dtoken.payload, function(err, revoked) {
            if (err) {
              callback(err);
            } else if (revoked) {
              callback(
                new UnauthorizedError("revoked_token", {
                  message: "The token has been revoked."
                })
              );
            } else {
              callback(null, decoded);
            }
          });
        }
      ],
      function(err, result) {
        if (err) {
          return next(err);
        }

        const principalId = extractPrincipalId(result);

        // parse the ARN from the incoming event
        var apiOptions = {};
        var tmp = event.methodArn.split(":");
        var apiGatewayArnTmp = tmp[5].split("/");
        var awsAccountId = tmp[4];
        apiOptions.region = tmp[3];
        apiOptions.restApiId = apiGatewayArnTmp[0];
        apiOptions.stage = apiGatewayArnTmp[1];

        // AuthPolicy was taken from AWS Blueprint
        const policy = new AuthPolicy(principalId, awsAccountId, apiOptions);

        // Allow user access to all methods
        policy.allowAllMethods();

        next(null, policy.build());
      }
    );
  };

  middleware.unless = unless;
  middleware.UnauthorizedError = UnauthorizedError;

  return middleware;
};

module.exports.UnauthorizedError = UnauthorizedError;
