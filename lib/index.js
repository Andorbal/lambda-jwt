var jwt = require("jsonwebtoken");
var UnauthorizedError = require("./errors/UnauthorizedError");
var async = require("async");
var AuthPolicy = require("./AuthPolicy");

var DEFAULT_REVOKED_FUNCTION = function(_, __, cb) {
  return cb(null, false);
};

function isFunction(object) {
  return Object.prototype.toString.call(object) === "[object Function]";
}

function flattenResult(data) {
  if (Object(data) !== data && !Array.isArray(data)) {
    return data;
  }

  var result = {};

  function recurse(cur, prop) {
    if (Object(cur) !== cur) {
      result[prop] = cur;
    } else if (Array.isArray(cur)) {
      for (var i = 0, l = cur.length; i < l; i++)
        recurse(cur[i], prop + "[" + i + "]");
      if (l == 0) result[prop] = [];
    } else {
      var isEmpty = true;
      for (var p in cur) {
        isEmpty = false;
        recurse(cur[p], prop ? prop + "." + p : p);
      }
      if (isEmpty && prop) result[prop] = {};
    }
  }
  recurse(data, "");
  return result;
}

function wrapStaticSecretInCallback(secret) {
  return function(_, __, cb) {
    return cb(null, secret);
  };
}

const createLogger = logger => {
  if (!logger) {
    return console;
  }

  return {
    error: isFunction(logger.error) ? logger.error : console.error,
    info: isFunction(logger.info) ? logger.info : console.info
  };
};

module.exports = function(options) {
  if (!options || !options.secret) throw new Error("secret should be set");

  var secretCallback = options.secret;
  var extractPrincipalId = options.extractPrincipalId || (x => x);
  if (typeof extractPrincipalId === "string") {
    const key = extractPrincipalId;
    extractPrincipalId = x => x[key];
  }

  if (!isFunction(secretCallback)) {
    secretCallback = wrapStaticSecretInCallback(secretCallback);
  }

  var isRevokedCallback = options.isRevoked || DEFAULT_REVOKED_FUNCTION;

  const logger = createLogger(options.logger);

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
          logger.error("Format is Authorization: Bearer [token]");
          return next("Unauthorized");
        }
      } else if (inputToken) {
        logger.error("Format is Authorization: Bearer [token]");
        return next("Unauthorized");
      }
    }

    if (!token) {
      logger.error("No authorization token was found");
      return next("Unauthorized");
    }

    var dtoken;

    try {
      dtoken = jwt.decode(token, { complete: true }) || {};
    } catch (err) {
      logger.error("Invalid token", err);
      return next("Unauthorized");
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
              logger.error("Invalid token", err);
              callback("Unauthorized");
            } else {
              callback(null, decoded);
            }
          });
        },
        function checkRevoked(decoded, callback) {
          isRevokedCallback({}, dtoken.payload, function(err, revoked) {
            if (err) {
              logger.error("Invalid token", err);
              callback("Unauthorized");
            } else if (revoked) {
              logger.error("The token has been revoked");
              callback("Unauthorized");
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
        const policyDoc = policy.build();
        policyDoc.context = flattenResult(result);

        next(null, policyDoc);
      }
    );
  };

  middleware.UnauthorizedError = UnauthorizedError;

  return middleware;
};

module.exports.UnauthorizedError = UnauthorizedError;
