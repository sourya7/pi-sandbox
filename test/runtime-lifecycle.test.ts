import test from "node:test";

import assert from "node:assert/strict";

import { RuntimeLifecycleGate } from "../src/runtime-lifecycle.ts";

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function tick(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
}

test("runtime mutation waits for active children and blocks new admission", async () => {
  const gate = new RuntimeLifecycleGate();
  const firstExit = deferred();
  const mutationExit = deferred();
  const order: string[] = [];

  const first = gate.runChild(async () => {
    order.push("first-start");
    await firstExit.promise;
    order.push("first-end");
  });
  await tick();

  const mutation = gate.mutate(async () => {
    order.push("mutation-start");
    await mutationExit.promise;
    order.push("mutation-end");
  });
  const second = gate.runChild(async () => {
    order.push("second-start");
  });
  await tick();
  assert.deepEqual(order, ["first-start"]);

  firstExit.resolve();
  await first;
  await tick();
  assert.deepEqual(order, ["first-start", "first-end", "mutation-start"]);

  mutationExit.resolve();
  await mutation;
  await second;
  assert.deepEqual(order, [
    "first-start",
    "first-end",
    "mutation-start",
    "mutation-end",
    "second-start",
  ]);
});

test("failed mutation releases waiting children and later mutations", async () => {
  const gate = new RuntimeLifecycleGate();
  await assert.rejects(
    gate.mutate(async () => Promise.reject(new Error("failed"))),
    /failed/,
  );
  await gate.runChild(async () => undefined);
  await gate.mutate(async () => undefined);
});
