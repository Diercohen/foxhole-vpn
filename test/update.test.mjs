// Pure check of the semver comparison used for update detection.
import assert from "node:assert";
import { newer, VERSION } from "../dist/update.js";

assert.equal(newer("1.0.0", "0.9.9"), true, "major up");
assert.equal(newer("0.2.0", "0.1.9"), true, "minor up");
assert.equal(newer("0.1.1", "0.1.0"), true, "patch up");
assert.equal(newer("0.1.0", "0.1.0"), false, "equal is not newer");
assert.equal(newer("0.1.0", "0.2.0"), false, "older is not newer");
assert.equal(newer("1.0.0", "0.99.99"), true, "major beats large minor/patch");
assert.ok(typeof VERSION === "string" && /\d+\.\d+\.\d+/.test(VERSION), "VERSION loaded from package.json");

console.log("ok - version compare detects newer releases");
