import assert from "node:assert";
import { test } from "node:test";

import { greet } from "../src/index.js";

test("greets", () => {
  assert.equal(greet("world"), "hello world");
});
