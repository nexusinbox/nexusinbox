import { describe, expect, it } from "vitest";
import { readCiphertextWithLimit } from "./attachment";

function streamOf(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
}

describe("readCiphertextWithLimit", () => {
  it("returns a body of exactly the verified size", async () => {
    const body = new Uint8Array([1, 2, 3, 4]);
    const buffer = await readCiphertextWithLimit(new Response(body), 4);
    expect(new Uint8Array(buffer)).toEqual(body);
  });

  it("assembles a streamed body split across chunks", async () => {
    const response = new Response(
      streamOf([new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5])]),
    );
    const buffer = await readCiphertextWithLimit(response, 5);
    expect(Array.from(new Uint8Array(buffer))).toEqual([1, 2, 3, 4, 5]);
  });

  it("stops at the first chunk past the verified size (swapped, oversized object)", async () => {
    let pulled = 0;
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        controller.enqueue(new Uint8Array(1024));
      },
    });
    await expect(readCiphertextWithLimit(new Response(endless), 4096)).rejects.toThrow(
      "attachment-size-mismatch",
    );
    // It must give up early rather than buffering the whole stream.
    expect(pulled).toBeLessThan(10);
  });

  it("rejects up front when Content-Length already exceeds the verified size", async () => {
    const response = new Response(new Uint8Array(8), {
      headers: { "content-length": String(5 * 1024 * 1024 * 1024) },
    });
    await expect(readCiphertextWithLimit(response, 8)).rejects.toThrow(
      "attachment-size-mismatch",
    );
  });

  it("rejects a body shorter than the verified size", async () => {
    await expect(
      readCiphertextWithLimit(new Response(new Uint8Array(3)), 4),
    ).rejects.toThrow("attachment-size-mismatch");
  });
});
