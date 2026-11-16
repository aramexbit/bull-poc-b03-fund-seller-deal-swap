# PoC — Bull SDK `fund()`: seller side, server-returned steps for an attacker deal executed without verification

## What it proves

The Bull SDK (`bull.mjs`, https://www.bull.family/sdk/bull.mjs) claims:
> "Safety: the API server is not trusted with your wallet. Every transaction
> it returns is checked before it is sent."

`fund()` breaks that promise on the seller side. It fetches the funding steps
from the API (`GET /api/v1/settle/{dealId}`) and sends every step whose
`from` is the connected wallet — without checking that the steps belong to
the deal the user intends to fund: no dealId binding, no sellAmount /
sellToken / buyer check, and no cap at all for token amounts (the ETH cap
is irrelevant: both steps carry value 0).

A compromised/malicious API server can therefore tell a seller "your deal is
#1" and return the steps for an attacker-created deal instead
(approve(escrow, 1,000,000) + fundTokens(attackerDeal)). The seller agreed
to sell 100 tokens; the SDK delivers 1,000,000. The attacker (buyer of
their own deal) funds 0.001 ETH and the swap settles: attacker receives
1,000,000 tokens for 0.001 ETH, victim loses their entire balance.

The attacker deal needs no seller consent on-chain: `createDeal` never
checks a seller signature — the seller's consent is only enforced by their
client verifying before funding, and `fund()` verifies nothing.

Why this is NOT a duplicate of B-02 (`open()` / `buyerReceive`): B-02 is
about the BUYER's `open()` not verifying the `createDeal` it sends. Fixing
`open()` does NOT fix this — the seller never calls `open()`. The
vulnerable function is `fund()`, the victim is the seller, and the
exploit path does not involve `open()` at all.

## Run (local only — no real funds, no mainnet, no Bull infrastructure)

```bash
# 1. Start Anvil (Foundry) on port 8545
anvil --port 8545 --chain-id 31337

# 2. Run (from this directory)
node run-poc.mjs
```

What happens:
1. Deploys `MockERC20`, mints 1,000,000 tokens to the victim (seller).
2. Attacker creates their own deal via the API: seller=victim,
   sellAmount=1,000,000, payAmount=0.001 ETH.
3. Victim calls `bull.fund(dealId)` to deliver the 100 tokens they agreed
   to sell. The mock API returns the attacker's steps; the real SDK sends
   approve(escrow, 1,000,000) + fundTokens(attackerDeal) with NO ERROR.
4. Attacker funds 0.001 ETH — swap settles.

## Result (verified 16 Nov 2026)

```
victim token balance before fund(): 1,000,000 (agreed to sell only 100)
SDK fund() returned 2 tx hashes — NO ERROR, NO WARNING
victim token balance after fund(): 0
victim RealToken balance: 0
attacker RealToken balance: 1,000,000
EXPLOITED: victim agreed to sell 100 tokens but fund() delivered 1,000,000 tokens into the attacker's deal for 0.001 ETH.
```

## Files

- `bull-sdk.mjs` — verbatim copy of https://www.bull.family/sdk/bull.mjs
  (sha256 `b8abb874115915485012abd954e9a0ea9951d66b42edb84e84583b5f52d52a0c`)
- `mock-api.mjs` — malicious mock Bull API (localhost only)
- `run-poc.mjs` — the PoC driver (real SDK + real BullEscrow on Anvil)
- `chain/src/BullEscrow.sol` — verbatim BullEscrow source (Sourcify, 4663)
- `chain/src/Mocks.sol` — MockERC20
- `poc-result.json` — machine-readable result of the last run

## Do NOT publish yet

This PoC is prepared for the Bull bug-bounty report form (whose PoC field
asks for a LINK). It must be published (repo) **only together with the
report submission**, after the user approves the draft — never before
(Bull's rules: no public disclosure until fixed). It contains no private
keys, no seed phrases, no real credentials: all wallets are throwaway keys
generated fresh on each run on a local Anvil chain.
