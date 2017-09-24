var jwt = require("jsonwebtoken");
var assert = require("assert");
var expressjwt = require("../lib");
var UnauthorizedError = require("../lib/errors/UnauthorizedError");

describe("failure tests", function() {
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
    expressjwt({
      secret: "shhhh"
    })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "credentials_required");
    });
  });

  it("should throw if authorization header is malformed", function() {
    event.headers = {};
    event.headers.authorization = "wrong";
    expressjwt({ secret: "shhhh" })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "credentials_bad_format");
    });
  });

  it("should throw if authorization header is not Bearer", function() {
    event.headers = {};
    event.headers.authorization = "Basic foobar";
    expressjwt({ secret: "shhhh" })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "credentials_bad_scheme");
    });
  });

  it("should throw if authorization header is not well-formatted jwt", function() {
    event.headers = {};
    event.headers.authorization = "Bearer wrongjwt";
    expressjwt({ secret: "shhhh" })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
    });
  });

  it("should throw if jwt is an invalid json", function() {
    event.headers = {};
    event.headers.authorization =
      "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.yJ1c2VybmFtZSI6InNhZ3VpYXIiLCJpYXQiOjE0NzEwMTg2MzUsImV4cCI6MTQ3MzYxMDYzNX0.foo";
    expressjwt({ secret: "shhhh" })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
    });
  });

  it("should throw if authorization header is not valid jwt", function() {
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar" }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({ secret: "different-shhhh" })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.message, "invalid signature");
    });
  });

  it("should throw if audience is not expected", function() {
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar", aud: "expected-audience" }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({
      secret: "shhhhhh",
      audience: "not-expected-audience"
    })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(
        err.message,
        "jwt audience invalid. expected: not-expected-audience"
      );
    });
  });

  it("should throw if token is expired", function() {
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar", exp: 1382412921 }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({ secret: "shhhhhh" })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.inner.name, "TokenExpiredError");
      assert.equal(err.message, "jwt expired");
    });
  });

  it("should throw if token issuer is wrong", function() {
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar", iss: "http://foo" }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({
      secret: "shhhhhh",
      issuer: "http://wrong"
    })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.message, "jwt issuer invalid. expected: http://wrong");
    });
  });

  it("should use errors thrown from custom getToken function", function() {
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar" }, secret);

    function getTokenThatThrowsError() {
      throw new UnauthorizedError("invalid_token", {
        message: "Invalid token!"
      });
    }

    expressjwt({
      secret: "shhhhhh",
      getToken: getTokenThatThrowsError
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
    expressjwt({ secret: secret })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.message, "invalid token");
    });
  });

  it("should throw error if token is expired even with when credentials are not required", function() {
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar", exp: 1382412921 }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({
      secret: secret,
      credentialsRequired: false
    })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.message, "jwt expired");
    });
  });

  it("should throw error if token is invalid even with when credentials are not required", function() {
    var secret = "shhhhhh";
    var token = jwt.sign({ foo: "bar", exp: 1382412921 }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({
      secret: "not the secret",
      credentialsRequired: false
    })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "invalid_token");
      assert.equal(err.message, "invalid signature");
    });
  });
});

describe("work tests", function() {
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

  it("should not work if no authorization header", function() {
    expressjwt({ secret: "shhhh" })(event, res, function(err) {
      assert(typeof err !== "undefined");
    });
  });

  it("should produce a stack trace that includes the failure reason", function() {
    var token = jwt.sign({ foo: "bar" }, "secretA");
    event.headers = {};
    event.headers.authorization = "Bearer " + token;

    expressjwt({ secret: "secretB" })(event, res, function(err) {
      var index = err.stack.indexOf("UnauthorizedError: invalid signature");
      assert.equal(
        index,
        0,
        "Stack trace didn't include 'invalid signature' message."
      );
    });
  });

  it("should work with a custom getToken function", function() {
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
      extractPrincipalId: x => x.foo
    })(event, res, function(err, policy) {
      assert.equal("bar", policy.principalId);
    });
  });

  it("should work with a secretCallback function that accepts header argument", function() {
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
      extractPrincipalId: x => x.foo
    })(event, res, function(err, policy) {
      assert.equal(undefined, err);
      assert.equal("bar", policy.principalId);
    });
  });
});
