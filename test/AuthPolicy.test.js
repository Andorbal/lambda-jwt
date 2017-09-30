var jwt = require("jsonwebtoken");
var assert = require("assert");

var AuthPolicy = require("../lib/AuthPolicy");

describe("build", function() {
  it("should throw error if no policy is set", function() {
    try {
      new AuthPolicy("foo", "bar").build();
    } catch (err) {
      assert.equal(err.message, "No statements defined for the policy");
    }
  });

  it("should set principal id", function() {
    const policy = new AuthPolicy("foo", "bar");
    policy.allowAllMethods();

    const policyDoc = policy.build();

    assert.equal(policyDoc.principalId, "foo");
  });

  describe("with single statement", function() {
    it("should set single statement on policy", function() {
      const policy = new AuthPolicy("foo", "bar");
      policy.allowAllMethods();

      const policyDoc = policy.build();

      assert.equal(policyDoc.policyDocument.Statement.length, 1);
      assert.equal(
        policyDoc.policyDocument.Statement[0].Action,
        "execute-api:Invoke"
      );
      assert.equal(policyDoc.policyDocument.Statement[0].Effect, "Allow");
    });

    it("should use verb and resource when set", function() {
      const policy = new AuthPolicy("foo", "bar");
      policy.allowMethod("GET", "quux");

      const policyDoc = policy.build();

      assert.equal(
        policyDoc.policyDocument.Statement[0].Resource[0],
        "arn:aws:execute-api:*:bar:*/*/GET/quux"
      );
    });

    it("should set default arn when no options set", function() {
      const policy = new AuthPolicy("foo", "bar");
      policy.allowAllMethods();

      const policyDoc = policy.build();

      assert.equal(
        policyDoc.policyDocument.Statement[0].Resource[0],
        "arn:aws:execute-api:*:bar:*/*/*/*"
      );
    });

    it("should set arn when options are set", function() {
      const policy = new AuthPolicy("foo", "bar", {
        region: "R",
        restApiId: "I",
        stage: "S"
      });
      policy.allowAllMethods();

      const policyDoc = policy.build();

      assert.equal(
        policyDoc.policyDocument.Statement[0].Resource[0],
        "arn:aws:execute-api:R:bar:I/S/*/*"
      );
    });
  });
});
