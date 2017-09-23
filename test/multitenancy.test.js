var jwt = require("jsonwebtoken");
var assert = require("assert");
var expressjwt = require("../lib");
var UnauthorizedError = require("../lib/errors/UnauthorizedError");

describe("multitenancy", function() {
  var event = {
    type: "REQUEST",
    methodArn:
      "arn:aws:execute-api:us-east-1:123456789012:s4x3opwd6i/test/GET/request"
  };

  var res = {};

  var tenants = {
    a: {
      secret: "secret-a"
    }
  };

  var secretCallback = function(event, payload, cb) {
    var issuer = payload.iss;
    if (tenants[issuer]) {
      return cb(null, tenants[issuer].secret);
    }

    return cb(
      new UnauthorizedError("missing_secret", {
        message: "Could not find secret for issuer."
      })
    );
  };

  var middleware = expressjwt({
    secret: secretCallback,
    extractPrincipalId: x => x.foo
  });

  it("should retrieve secret using callback", function() {
    var token = jwt.sign({ iss: "a", foo: "bar" }, tenants.a.secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;

    middleware(event, res, function(err, policy) {
      assert.equal("bar", policy.principalId);
    });
  });

  it("should throw if an error ocurred when retrieving the token", function() {
    var secret = "shhhhhh";
    var token = jwt.sign({ iss: "inexistent", foo: "bar" }, secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;

    middleware(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "missing_secret");
      assert.equal(err.message, "Could not find secret for issuer.");
    });
  });

  it("should fail if token is revoked", function() {
    var token = jwt.sign({ iss: "a", foo: "bar" }, tenants.a.secret);

    event.headers = {};
    event.headers.authorization = "Bearer " + token;

    var middleware = expressjwt({
      secret: secretCallback,
      isRevoked: function(event, payload, done) {
        done(null, true);
      }
    })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "revoked_token");
      assert.equal(err.message, "The token has been revoked.");
    });
  });
});
