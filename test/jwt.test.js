var jwt = require("jsonwebtoken");
var assert = require("assert");
var expressjwt = require("../lib");
var UnauthorizedError = require("../lib/errors/UnauthorizedError");
const createLogger = require("./testLogger");

describe("failure tests", function() {
  const logger = createLogger();
  const event = {
    type: "REQUEST",
    methodArn:
      "arn:aws:execute-api:us-east-1:123456789012:s4x3opwd6i/test/GET/request"
  };
  var res = {};

  it("should throw if options not sent", function() {
    try {
      expressjwt();
    } catch (e) {
      assert.ok(e);
      assert.equal(e.message, "secret should be set");
    }
  });

  it("should throw if no authorization header and credentials are required", function() {
    const logger = createLogger();
    expressjwt({
      secret: "shhhh",
      logger
    })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err, "Unauthorized");
      assert.equal(logger.error.args[0][0], "No authorization token was found");
    });
  });

  it("should throw if authorization header is malformed", function() {
    const logger = createLogger();
    event.headers = {};
    event.headers.authorization = "wrong";
    expressjwt({ secret: "shhhh", logger })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err, "Unauthorized");
      assert.equal(
        logger.error.args[0][0],
        "Format is Authorization: Bearer [token]"
      );
    });
  });

  it("should throw if authorization header is not Bearer", function() {
    const logger = createLogger();
    event.headers = {};
    event.headers.authorization = "Basic foobar";
    expressjwt({ secret: "shhhh", logger })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err, "Unauthorized");
      assert.equal(
        logger.error.args[0][0],
        "Format is Authorization: Bearer [token]"
      );
    });
  });

  it("should throw if authorization header is not well-formatted jwt", function() {
    const logger = createLogger();
    event.headers = {};
    event.headers.authorization = "Bearer wrongjwt";
    expressjwt({ secret: "shhhh", logger })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err, "Unauthorized");
      assert.equal(logger.error.args[0][1].message, "jwt malformed");
    });
  });

  it("should throw if jwt is an invalid json", function() {
    const logger = createLogger();
    event.headers = {};
    event.headers.authorization =
      "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.yJ1c2VybmFtZSI6InNhZ3VpYXIiLCJpYXQiOjE0NzEwMTg2MzUsImV4cCI6MTQ3MzYxMDYzNX0.foo";
    expressjwt({ secret: "shhhh", logger })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err, "Unauthorized");
      assert.equal(
        logger.error.args[0][1].message,
        "Unexpected token ȝ in JSON at position 0"
      );
    });
  });

  it("should throw if authorization header is not valid jwt", function() {
    const logger = createLogger();
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar" }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({ secret: "different-shhhh", logger })(event, res, function(
      err
    ) {
      assert.ok(err);
      assert.equal(err, "Unauthorized");
      assert.equal(logger.error.args[0][1].message, "invalid signature");
    });
  });

  it("should throw if audience is not expected", function() {
    const logger = createLogger();
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar", aud: "expected-audience" }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({
      secret: "shhhhhh",
      audience: "not-expected-audience",
      logger
    })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err, "Unauthorized");
      assert.equal(
        logger.error.args[0][1].message,
        "jwt audience invalid. expected: not-expected-audience"
      );
    });
  });

  it("should throw if token is expired", function() {
    const logger = createLogger();
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar", exp: 1382412921 }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({ secret: "shhhhhh", logger })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err, "Unauthorized");
      assert.equal(logger.error.args[0][0], "Invalid token");
    });
  });

  it("should throw if token issuer is wrong", function() {
    const logger = createLogger();
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar", iss: "http://foo" }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({
      secret: "shhhhhh",
      issuer: "http://wrong",
      logger
    })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err, "Unauthorized");
      assert.equal(
        logger.error.args[0][1].message,
        "jwt issuer invalid. expected: http://wrong"
      );
    });
  });

  it("should use errors thrown from custom getToken function", function() {
    const logger = createLogger();
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar" }, secret);

    function getTokenThatThrowsError() {
      throw new UnauthorizedError("invalid_token", {
        message: "Invalid token!"
      });
    }

    expressjwt({
      secret: "shhhhhh",
      getToken: getTokenThatThrowsError,
      logger
    })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.message, "Invalid token!");
    });
  });

  it("should throw error when signature is wrong", function() {
    var secret = "shhh";
    var token = jwt.sign({ foo: "bar", iss: "http://www" }, secret);
    // manipulate the token
    var newContent = new Buffer("{foo: 'bar', edg: 'ar'}").toString("base64");
    var splitetToken = token.split(".");
    splitetToken[1] = newContent;
    var newToken = splitetToken.join(".");

    // build eventuest
    event.headers = [];
    event.headers.authorization = "Bearer " + newToken;
    expressjwt({ secret: secret, logger })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err, "Unauthorized");
      assert.equal(logger.error.args[0][0], "Invalid token");
    });
  });

  it("should throw error if token is expired even with when credentials are not required", function() {
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar", exp: 1382412921 }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({
      secret: secret,
      credentialsRequired: false,
      logger
    })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err, "Unauthorized");
      assert.equal(logger.error.args[0][0], "Invalid token");
    });
  });

  it("should throw error if token is invalid even with when credentials are not required", function() {
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar", exp: 1382412921 }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({
      secret: "not the secret",
      credentialsRequired: false,
      logger
    })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err, "Unauthorized");
      assert.equal(logger.error.args[0][0], "Invalid token");
    });
  });
});

describe("work tests", function() {
  const logger = createLogger();
  const event = {
    type: "REQUEST",
    methodArn:
      "arn:aws:execute-api:us-east-1:123456789012:s4x3opwd6i/test/GET/request"
  };
  var res = {};

  it("should work if authorization header is valid jwt", function() {
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar" }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({
      secret: secret,
      extractPrincipalId: "foo"
    })(event, res, function(_, policy) {
      assert.equal("bar", policy.principalId);
    });
  });

  it("should work if authorization header is valid with a buffer secret", function() {
    var secret = new Buffer(
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "base64"
    );
    var token = jwt.sign({ foo: "bar" }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({
      secret: secret,
      extractPrincipalId: "foo"
    })(event, res, function(err, policy) {
      assert.equal("bar", policy.principalId);
    });
  });

  it("should use property if extractPrincipalId is string", function() {
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar" }, secret);

    res = {};
    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({
      secret: secret,
      extractPrincipalId: "foo"
    })(event, res, function(err, policy) {
      assert.equal("bar", policy.principalId);
    });
  });

  it("should use result when extractPrincipalId is function", function() {
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar" }, secret);

    res = {};
    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({
      secret: secret,
      extractPrincipalId: x => x.foo.toUpperCase()
    })(event, res, function(err, policy) {
      assert.equal("BAR", policy.principalId);
    });
  });

  describe("context", function() {
    function execute(token, callback) {
      var secret = "shhhhhh";
      var token = jwt.sign(token, secret);

      res = {};
      event.headers = {};
      event.headers.authorization = "Bearer " + token;
      expressjwt({
        secret: secret,
        extractPrincipalId: "foo"
      })(event, res, function(err, policy) {
        callback(policy);
      });
    }

    it("should be string when token is string", function() {
      execute("foo", function(policy) {
        assert.equal(policy.context, "foo");
      });
    });

    it("should be json with simple values", function() {
      execute({ s: "s", n: 1, b: true }, function(policy) {
        assert.equal(policy.context.s, "s");
        assert.equal(policy.context.n, 1);
        assert.equal(policy.context.b, true);
      });
    });

    it("should be json with flattened keys", function() {
      execute({ root: { nested: "foo" } }, function(policy) {
        assert.equal(policy.context["root.nested"], "foo");
      });
    });
  });

  it("should not work if no authorization header", function() {
    const logger = createLogger();
    expressjwt({ secret: "shhhh", logger })(event, res, function(err) {
      assert(typeof err !== "undefined");
    });
  });

  it("should work with a custom getToken function", function() {
    const logger = createLogger();
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar" }, secret);

    event.headers = {};
    event.queryStringParameters = {};
    event.queryStringParameters.token = token;

    function getTokenFromQuery(event) {
      return event.queryStringParameters.token;
    }

    expressjwt({
      secret: secret,
      getToken: getTokenFromQuery,
      extractPrincipalId: x => x.foo,
      logger
    })(event, res, function(err, policy) {
      assert.equal("bar", policy.principalId);
    });
  });

  it("should work with a secretCallback function that accepts header argument", function() {
    const logger = createLogger();
    var secret = "shhhhhh";
    var secretCallback = function(_, headers, payload, cb) {
      assert.equal(headers.alg, "HS256");
      assert.equal(payload.foo, "bar");
      process.nextTick(function() {
        return cb(null, secret);
      });
    };
    var token = jwt.sign({ foo: "bar" }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({
      secret: secretCallback,
      extractPrincipalId: x => x.foo,
      logger
    })(event, res, function(err, policy) {
      assert.equal(undefined, err);
      assert.equal("bar", policy.principalId);
    });
  });
});
