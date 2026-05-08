#!/usr/bin/env node
import net from "node:net";

const socketPath = process.env.AGENT_INBOX_GATEWAY_SOCKET || "/tmp/nexusinbox-gateway.sock";
const [, , method, paramsArg] = process.argv;

if (!method) {
  console.error("Usage: node scripts/gateway_rpc.mjs <method> ['{\"key\":\"value\"}']");
  process.exit(1);
}

let params = {};
if (paramsArg) {
  try {
    params = JSON.parse(paramsArg);
  } catch (error) {
    console.error("Invalid JSON params:", error.message);
    process.exit(1);
  }
}

const request = {
  id: 1,
  method,
  params,
};

const socket = net.createConnection(socketPath);
let buffer = "";

socket.on("connect", () => {
  socket.write(`${JSON.stringify(request)}\n`);
});

socket.on("data", (chunk) => {
  buffer += chunk.toString("utf8");
  const newlineIndex = buffer.indexOf("\n");
  if (newlineIndex === -1) {
    return;
  }

  const line = buffer.slice(0, newlineIndex).trim();
  socket.end();

  try {
    const response = JSON.parse(line);
    console.log(JSON.stringify(response, null, 2));
    if (response.error) {
      process.exitCode = 1;
    }
  } catch (error) {
    console.error("Invalid gateway response:", error.message);
    process.exit(1);
  }
});

socket.on("error", (error) => {
  console.error(`Failed to connect to gateway socket ${socketPath}:`, error.message);
  process.exit(1);
});
