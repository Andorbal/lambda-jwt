var jwt = require("jsonwebtoken");
var assert = require("assert");

var expressjwt = require("../lib");
var UnauthorizedError = require("../lib/errors/UnauthorizedError");

describe("string tokens", function() {
  var event = {};
  var res = {};

  it("should work with a valid string token", function() {
    var secret = "shhhhhh";
    var token = jwt.sign("foo", secret);

    event.type = "REQUEST";
    event.methodArn =
      "arn:aws:execute-api:us-east-1:123456789012:s4x3opwd6i/test/GET/request";
    event.headers = {};
    event.headers.authorization = "Bearer " + token;
    expressjwt({ secret: secret })(event, res, function(err, policy) {
      assert.equal("foo", policy.principalId);
    });
  });
});
