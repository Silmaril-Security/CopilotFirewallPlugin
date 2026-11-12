import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";

const [responsePath, toolName] = process.argv.slice(2);
const responseText = readFileSync(responsePath, "utf8");

const RESULTS = {
  initialize: (params) => ({
    protocolVersion: params.protocolVersion,
    capabilities: { tools: {} },
    serverInfo: { name: "native-acceptance", version: "1.0.0" },
  }),
  ping: () => ({}),
  "tools/list": () => ({
    tools: [{
      name: toolName,
      description: "Return the staged notes text.",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
    }],
  }),
  "tools/call": () => ({
    content: [{ type: "text", text: responseText }],
    isError: false,
  }),
};

for await (const line of createInterface({ input: process.stdin })) {
  const message = JSON.parse(line);
  if (message.id === undefined) continue;
  const result = RESULTS[message.method];
  process.stdout.write(`${JSON.stringify(result
    ? { jsonrpc: "2.0", id: message.id, result: result(message.params) }
    : { jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } })}\n`);
}
