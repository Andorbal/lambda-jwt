var jwt = require("jsonwebtoken");
var assert = require("assert");
var expressjwt = require("../lib");
var UnauthorizedError = require("../lib/errors/UnauthorizedError");

describe("revoked jwts", function() {
  var secret = "shhhhhh";

  var revoked_id = "1234";

  var middleware = expressjwt({
    secret: secret,
    isRevoked: function(event, payload, done) {
      done(null, payload.jti && payload.jti === revoked_id);
    },
    extractPrincipalId: x => x.foo
  });

  it("should throw if token is revoked", function() {
    var event = {};
    var res = {};
    var token = jwt.sign({ jti: revoked_id, foo: "bar" }, secret);

    event.type = "REQUEST";
    event.methodArn =
      "arn:aws:execute-api:us-east-1:123456789012:s4x3opwd6i/test/GET/request";
    event.headers = {};
    event.headers.authorization = "Bearer " + token;

    middleware(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.code, "revoked_token");
      assert.equal(err.message, "The token has been revoked.");
    });
  });

  it("should work if token is not revoked", function() {
    var event = {};
    var res = {};
    var token = jwt.sign({ jti: "1233", foo: "bar" }, secret);

    event.type = "REQUEST";
    event.methodArn =
      "arn:aws:execute-api:us-east-1:123456789012:s4x3opwd6i/test/GET/request";
    event.headers = {};
    event.headers.authorization = "Bearer " + token;

    middleware(event, res, function(err, policy) {
      assert.equal("bar", policy.principalId);
    });
  });

  it("should throw if error occurs checking if token is revoked", function() {
    var event = {};
    var res = {};
    var token = jwt.sign({ jti: revoked_id, foo: "bar" }, secret);

    event.type = "REQUEST";
    event.methodArn =
      "arn:aws:execute-api:us-east-1:123456789012:s4x3opwd6i/test/GET/request";
    event.headers = {};
    event.headers.authorization = "Bearer " + token;

    expressjwt({
      secret: secret,
      isRevoked: function(event, payload, done) {
        done(new Error("An error ocurred"));
      }
    })(event, res, function(err) {
      assert.ok(err);
      assert.equal(err.message, "An error ocurred");
    });
  });
});
