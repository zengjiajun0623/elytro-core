/**
 * elytro-agent — agent-facing CLI for the elytro-core agent-native smart account.
 *
 * The human delegates once (`grant`), then the agent operates autonomously
 * within on-chain realized-value caps (`send`) — and can ask, before acting,
 * whether it's within its envelope (`check`). All output is deterministic JSON
 * for agent parsing: { "success": true, "result": {...} } | { "success": false,
 * "error": { "code", "message", "hint", "suggestion" } }.
 *
 * Config via env (or flags): ELYTRO_RPC, ELYTRO_ENTRYPOINT, ELYTRO_FACTORY,
 * ELYTRO_OWNER_KEY, ELYTRO_AGENT_KEY, ELYTRO_CHAIN_ID.
 */
import { Command } from 'commander';
import {
  createPublicClient,
  createWalletClient,
  http,
  defineChain,
  encodeFunctionData,
  decodeErrorResult,
  parseEventLogs,
  keccak256,
  toHex,
  toBytes,
  isAddress,
  getAddress,
  BaseError,
  ContractFunctionRevertedError,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const ENTRYPOINT_DEFAULT = '0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108' as Address;
const TRANSFER_SELECTOR = '0xa9059cbb' as Hex;
// Defaults target the Cleave testnet (chain 73571) so a fresh install works
// out of the box; override any of them with env vars or flags.
const CLEAVE_RPC = 'https://foundry-production-85dd.up.railway.app';
const CLEAVE_FACTORY = '0xd7D5f4A79c5042161324376F37Dd3Db7bd3E5C2F' as Address;
// Cleave Earn (P / yield leg) testnet defaults for the `earn` verb — override with flags.
const CLEAVE_ZAP = '0x889f96D66d7E396d60309F3E151e08a91eEdEe25' as Address;
const CLEAVE_SERIES = '0x9f1ac54BEF0DD2f6f3462EA0fa94fC62300d3a8e' as Address;
const CLEAVE_USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' as Address;
const KEY_DIR = join(homedir(), '.elytro-agent');
const KEY_FILE = join(KEY_DIR, 'agent.key');

/// Resolve the AGENT session key: flag > env > stored vault file (from `keygen`).
function loadAgentKey(opts: Record<string, string | undefined>): Hex {
  const fromFile = existsSync(KEY_FILE) ? (readFileSync(KEY_FILE, 'utf8').trim() as Hex) : undefined;
  const key = (opts.agentKey || process.env.ELYTRO_AGENT_KEY || fromFile) as Hex | undefined;
  if (!key) fail(-32001, 'No agent key. Run `elytro-agent keygen` once (or set ELYTRO_AGENT_KEY).');
  return key!;
}

// ─── output ──────────────────────────────────────────────────────
function ok(result: unknown): never {
  process.stdout.write(JSON.stringify({ success: true, result }, bigintReplacer, 2) + '\n');
  process.exit(0);
}
function fail(code: number, message: string, extra: Record<string, unknown> = {}): never {
  process.stdout.write(
    JSON.stringify({ success: false, error: { code, message, ...extra } }, bigintReplacer, 2) + '\n',
  );
  process.exit(1);
}
function bigintReplacer(_k: string, v: unknown) {
  return typeof v === 'bigint' ? v.toString() : v;
}

// ─── ABIs (minimal) ──────────────────────────────────────────────
const CALL_TUPLE = {
  type: 'tuple[]',
  components: [
    { name: 'target', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'data', type: 'bytes' },
  ],
} as const;

const USEROP_TUPLE = {
  type: 'tuple',
  components: [
    { name: 'sender', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'initCode', type: 'bytes' },
    { name: 'callData', type: 'bytes' },
    { name: 'accountGasLimits', type: 'bytes32' },
    { name: 'preVerificationGas', type: 'uint256' },
    { name: 'gasFees', type: 'bytes32' },
    { name: 'paymasterAndData', type: 'bytes' },
    { name: 'signature', type: 'bytes' },
  ],
} as const;

const FACTORY_ABI = [
  { type: 'function', name: 'getAddress', stateMutability: 'view', inputs: [{ name: 'owner', type: 'address' }, { name: 'salt', type: 'bytes32' }], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'createAccount', stateMutability: 'nonpayable', inputs: [{ name: 'owner', type: 'address' }, { name: 'salt', type: 'bytes32' }], outputs: [{ type: 'address' }] },
] as const;

const ACCOUNT_ABI = [
  { type: 'function', name: 'owner', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'agents', stateMutability: 'view', inputs: [{ type: 'address' }], outputs: [{ name: 'active', type: 'bool' }, { name: 'notBefore', type: 'uint48' }, { name: 'expiresAt', type: 'uint48' }] },
  { type: 'function', name: 'allowedCall', stateMutability: 'view', inputs: [{ type: 'address' }, { type: 'address' }, { type: 'bytes4' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'isProtected', stateMutability: 'view', inputs: [{ type: 'address' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'setProtectedToken', stateMutability: 'nonpayable', inputs: [{ type: 'address' }, { type: 'bool' }], outputs: [] },
  { type: 'function', name: 'setAgent', stateMutability: 'nonpayable', inputs: [{ type: 'address' }, { type: 'uint48' }, { type: 'uint48' }, { type: 'bool' }], outputs: [] },
  { type: 'function', name: 'setAllowedCall', stateMutability: 'nonpayable', inputs: [{ type: 'address' }, { type: 'address' }, { type: 'bytes4' }, { type: 'bool' }], outputs: [] },
  { type: 'function', name: 'setCap', stateMutability: 'nonpayable', inputs: [{ type: 'address' }, { type: 'address' }, { type: 'uint256' }, { type: 'uint256' }, { type: 'uint256' }, { type: 'uint256' }], outputs: [] },
  { type: 'function', name: 'executeUserOp', stateMutability: 'nonpayable', inputs: [CALL_TUPLE], outputs: [{ type: 'bytes[]' }] },
  {
    type: 'function', name: 'getCap', stateMutability: 'view',
    inputs: [{ type: 'address' }, { type: 'address' }],
    outputs: [{
      type: 'tuple', components: [
        { name: 'set', type: 'bool' }, { name: 'perTx', type: 'uint256' }, { name: 'perPeriod', type: 'uint256' },
        { name: 'period', type: 'uint256' }, { name: 'total', type: 'uint256' }, { name: 'spentPeriod', type: 'uint256' },
        { name: 'periodStart', type: 'uint48' }, { name: 'spentTotal', type: 'uint256' },
      ],
    }],
  },
] as const;

const ENTRYPOINT_ABI = [
  { type: 'function', name: 'getNonce', stateMutability: 'view', inputs: [{ type: 'address' }, { type: 'uint192' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'getUserOpHash', stateMutability: 'view', inputs: [USEROP_TUPLE], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'handleOps', stateMutability: 'nonpayable', inputs: [{ ...USEROP_TUPLE, type: 'tuple[]' }, { type: 'address' }], outputs: [] },
  // The EntryPoint catches inner UserOp reverts and STILL mines the bundle, so
  // these events (not the tx receipt status) are the authoritative outcome.
  { type: 'event', name: 'UserOperationEvent', inputs: [
    { name: 'userOpHash', type: 'bytes32', indexed: true }, { name: 'sender', type: 'address', indexed: true },
    { name: 'paymaster', type: 'address', indexed: true }, { name: 'nonce', type: 'uint256', indexed: false },
    { name: 'success', type: 'bool', indexed: false }, { name: 'actualGasCost', type: 'uint256', indexed: false },
    { name: 'actualGasUsed', type: 'uint256', indexed: false },
  ] },
  { type: 'event', name: 'UserOperationRevertReason', inputs: [
    { name: 'userOpHash', type: 'bytes32', indexed: true }, { name: 'sender', type: 'address', indexed: true },
    { name: 'nonce', type: 'uint256', indexed: false }, { name: 'revertReason', type: 'bytes', indexed: false },
  ] },
] as const;

// AgentAccount custom errors, used to decode an inner UserOp revert reason into
// a meaningful agent-facing code. (Plus the Solidity built-ins.)
const ACCOUNT_ERRORS = [
  { type: 'error', name: 'AgentInactive', inputs: [] },
  { type: 'error', name: 'AgentNotYetValid', inputs: [] },
  { type: 'error', name: 'AgentExpired', inputs: [] },
  { type: 'error', name: 'SelfCallForbidden', inputs: [] },
  { type: 'error', name: 'ApprovalForbidden', inputs: [] },
  { type: 'error', name: 'MalformedCalldata', inputs: [] },
  { type: 'error', name: 'UnprotectedTokenTransfer', inputs: [{ name: 'token', type: 'address' }] },
  { type: 'error', name: 'CallNotAllowlisted', inputs: [{ name: 'target', type: 'address' }, { name: 'selector', type: 'bytes4' }] },
  { type: 'error', name: 'CallFailed', inputs: [{ name: 'index', type: 'uint256' }, { name: 'ret', type: 'bytes' }] },
  { type: 'error', name: 'UncappedProtectedAssetMoved', inputs: [{ name: 'asset', type: 'address' }] },
  { type: 'error', name: 'PerTxCapExceeded', inputs: [{ name: 'asset', type: 'address' }, { name: 'outflow', type: 'uint256' }, { name: 'cap', type: 'uint256' }] },
  { type: 'error', name: 'PerPeriodCapExceeded', inputs: [{ name: 'asset', type: 'address' }, { name: 'wouldSpend', type: 'uint256' }, { name: 'cap', type: 'uint256' }] },
  { type: 'error', name: 'TotalCapExceeded', inputs: [{ name: 'asset', type: 'address' }, { name: 'wouldSpend', type: 'uint256' }, { name: 'cap', type: 'uint256' }] },
  { type: 'error', name: 'BalanceQueryFailed', inputs: [{ name: 'token', type: 'address' }] },
  { type: 'error', name: 'Error', inputs: [{ name: 'reason', type: 'string' }] },
  { type: 'error', name: 'Panic', inputs: [{ name: 'code', type: 'uint256' }] },
] as const;
// Errors the OWNER must resolve by changing the grant/config → escalate (-32010).
// Everything else (funding, sick token) is an execution failure → -32012.
const ESCALATE_ERRORS = new Set([
  'PerTxCapExceeded', 'PerPeriodCapExceeded', 'TotalCapExceeded', 'UncappedProtectedAssetMoved',
  'AgentExpired', 'AgentInactive', 'AgentNotYetValid', 'CallNotAllowlisted', 'UnprotectedTokenTransfer',
]);
function decodeRevert(data: Hex): { name: string; args: readonly unknown[] } | null {
  try {
    const d = decodeErrorResult({ abi: ACCOUNT_ERRORS, data });
    return { name: d.errorName, args: (d.args ?? []) as readonly unknown[] };
  } catch {
    return null;
  }
}

const ERC20_ABI = [
  { type: 'function', name: 'balanceOf', stateMutability: 'view', inputs: [{ type: 'address' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'transfer', stateMutability: 'nonpayable', inputs: [{ type: 'address' }, { type: 'uint256' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'decimals', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint8' }] },
  { type: 'function', name: 'symbol', stateMutability: 'view', inputs: [], outputs: [{ type: 'string' }] },
] as const;

// Cleave Zap (Earn leg): yieldBuy pulls quote (USDC) from the account via a
// standing owner-set allowance and routes it through Uniswap to mint P to the
// account. The realized-value engine charges the MEASURED USDC outflow against
// the agent's cap — so the agent is bounded even though a router moves the value.
const ZAP_ABI = [
  { type: 'function', name: 'yieldBuy', stateMutability: 'nonpayable',
    inputs: [{ name: 'series', type: 'address' }, { name: 'poolFee', type: 'uint24' }, { name: 'quoteIn', type: 'uint256' }, { name: 'minPOut', type: 'uint256' }, { name: 'deadline', type: 'uint256' }],
    outputs: [{ name: 'pOut', type: 'uint256' }] },
  // boostFull buys the upside (N) leg with NATIVE ETH (payable) — no approve
  // needed. The realized-value engine charges the measured native-ETH outflow
  // (value sent − ethBack) against the agent's native (address(0)) cap.
  { type: 'function', name: 'boostFull', stateMutability: 'payable',
    inputs: [{ name: 'series', type: 'address' }, { name: 'poolFee', type: 'uint24' }, { name: 'wethFee', type: 'uint24' }, { name: 'rounds', type: 'uint256' }, { name: 'minNOut', type: 'uint256' }, { name: 'deadline', type: 'uint256' }],
    outputs: [{ name: 'nOut', type: 'uint256' }, { name: 'ethBack', type: 'uint256' }] },
] as const;
const SERIES_ABI = [
  { type: 'function', name: 'P', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'N', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
] as const;
const NATIVE_ASSET = '0x0000000000000000000000000000000000000000' as Address;
// Faithful `earn` preflight: eth_call the DIRECT agent path with the account's
// custom errors in-ABI so viem decodes a revert into the exact error name.
const EXEC_AGENT_ABI = [
  { type: 'function', name: 'executeAsAgent', stateMutability: 'nonpayable', inputs: [CALL_TUPLE], outputs: [{ type: 'bytes[]' }] },
] as const;
const SIM_ABI = [...EXEC_AGENT_ABI, ...ACCOUNT_ERRORS] as const;

// ─── config ──────────────────────────────────────────────────────
function cfg(opts: Record<string, string | undefined>) {
  const rpc = opts.rpc || process.env.ELYTRO_RPC || CLEAVE_RPC;
  const chainId = Number(opts.chainId || process.env.ELYTRO_CHAIN_ID || '73571');
  const chain = defineChain({
    id: chainId,
    name: `chain-${chainId}`,
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [rpc!] } },
  });
  const pub = createPublicClient({ chain, transport: http(rpc!) });
  const entryPoint = (opts.entrypoint || process.env.ELYTRO_ENTRYPOINT || ENTRYPOINT_DEFAULT) as Address;
  const factory = (opts.factory || process.env.ELYTRO_FACTORY || CLEAVE_FACTORY) as Address;
  return { rpc: rpc!, chain, pub, entryPoint, factory };
}
function ownerWallet(c: ReturnType<typeof cfg>, opts: Record<string, string | undefined>) {
  const key = (opts.ownerKey || process.env.ELYTRO_OWNER_KEY) as Hex | undefined;
  if (!key) fail(-32001, 'No owner key. Set ELYTRO_OWNER_KEY or pass --owner-key.');
  return createWalletClient({ account: privateKeyToAccount(key!), chain: c.chain, transport: http(c.rpc) });
}
function agentAccount(opts: Record<string, string | undefined>) {
  return privateKeyToAccount(loadAgentKey(opts));
}
function saltOf(s: string): Hex {
  return s.startsWith('0x') && s.length === 66 ? (s as Hex) : keccak256(toBytes(s));
}
function pack128(hi: bigint, lo: bigint): Hex {
  return toHex((hi << 128n) | lo, { size: 32 });
}
async function legacyGas(c: ReturnType<typeof cfg>) {
  return await c.pub.getGasPrice();
}

// ─── program ─────────────────────────────────────────────────────
const program = new Command();
program.name('elytro-agent').description('Agent-native smart account CLI (realized-value caps + guardian recovery)');
const common = (cmd: Command) =>
  cmd
    .option('--rpc <url>')
    .option('--chain-id <id>')
    .option('--entrypoint <addr>')
    .option('--factory <addr>')
    .option('--owner-key <hex>')
    .option('--agent-key <hex>');

// address: counterfactual account address
common(program.command('address'))
  .requiredOption('--owner <addr>')
  .option('--salt <s>', 'salt (string hashed to bytes32, or 0x32bytes)', 'default')
  .action(async (o) => {
    const c = cfg(o);
    if (!c.factory) fail(-32001, 'No factory. Set ELYTRO_FACTORY or pass --factory.');
    if (!isAddress(o.owner)) fail(-32602, `Invalid --owner ${o.owner}`);
    const addr = await c.pub.readContract({ address: c.factory, abi: FACTORY_ABI, functionName: 'getAddress', args: [getAddress(o.owner), saltOf(o.salt)] });
    ok({ account: addr, owner: getAddress(o.owner), salt: saltOf(o.salt) });
  });

// create: deploy the account (owner authority)
common(program.command('create'))
  .option('--salt <s>', 'salt', 'default')
  .action(async (o) => {
    const c = cfg(o);
    if (!c.factory) fail(-32001, 'No factory.');
    const w = ownerWallet(c, o);
    const owner = w.account!.address;
    const predicted = await c.pub.readContract({ address: c.factory, abi: FACTORY_ABI, functionName: 'getAddress', args: [owner, saltOf(o.salt)] });
    const code = await c.pub.getBytecode({ address: predicted });
    if (code && code !== '0x') ok({ account: predicted, owner, status: 'already_deployed' });
    const hash = await w.writeContract({ address: c.factory, abi: FACTORY_ABI, functionName: 'createAccount', args: [owner, saltOf(o.salt)], gasPrice: await legacyGas(c) });
    const r = await c.pub.waitForTransactionReceipt({ hash });
    ok({ account: predicted, owner, txHash: hash, status: r.status });
  });

// grant: human delegates a scoped capability to an agent
common(program.command('grant'))
  .requiredOption('--account <addr>')
  .requiredOption('--agent <addr>')
  .requiredOption('--token <addr>')
  .requiredOption('--per-tx <atomic>')
  .requiredOption('--total <atomic>')
  .option('--expires-in <sec>', 'validity seconds from now', '2592000')
  .action(async (o) => {
    const c = cfg(o);
    const w = ownerWallet(c, o);
    for (const [k, v] of [['account', o.account], ['agent', o.agent], ['token', o.token]] as const)
      if (!isAddress(v)) fail(-32602, `Invalid --${k} ${v}`);
    const acct = getAddress(o.account), agent = getAddress(o.agent), token = getAddress(o.token);
    const expiresAt = Math.floor(Date.now() / 1000) + Number(o.expiresIn);
    const gp = await legacyGas(c);
    const send = (fn: string, args: unknown[]) => w.writeContract({ address: acct, abi: ACCOUNT_ABI, functionName: fn as never, args: args as never, gasPrice: gp });
    const txs: Record<string, Hex> = {};
    txs.protect = await send('setProtectedToken', [token, true]);
    await c.pub.waitForTransactionReceipt({ hash: txs.protect });
    txs.agent = await send('setAgent', [agent, 0, expiresAt, true]);
    await c.pub.waitForTransactionReceipt({ hash: txs.agent });
    txs.allow = await send('setAllowedCall', [agent, token, TRANSFER_SELECTOR, true]);
    await c.pub.waitForTransactionReceipt({ hash: txs.allow });
    txs.cap = await send('setCap', [agent, token, BigInt(o.perTx), 0n, 0n, BigInt(o.total)]);
    await c.pub.waitForTransactionReceipt({ hash: txs.cap });
    ok({ status: 'granted', account: acct, agent, token, perTx: o.perTx, total: o.total, expiresAt, txs });
  });

// check: would this action be authorized AND executable? Backed by a faithful
// simulation of on-chain enforcement (cap incl. perPeriod, balance, allowlist,
// expiry) — not pure arithmetic. Pass --to to also simulate the real transfer.
common(program.command('check'))
  .requiredOption('--account <addr>')
  .requiredOption('--agent <addr>')
  .requiredOption('--token <addr>')
  .requiredOption('--amount <atomic>')
  .option('--to <addr>', 'recipient (enables a real transfer simulation)')
  .action(async (o) => {
    const c = cfg(o);
    const sim = await simulateSend(c, getAddress(o.account), getAddress(o.token), o.to ? getAddress(o.to) : undefined, BigInt(o.amount), getAddress(o.agent));
    const decision = sim.decision === 'allow' ? 'allow' : 'escalate';
    ok({
      decision, predictedError: sim.predictedError, reasons: sim.reasons,
      cap: sim.cap, headroom: sim.headroom, checks: sim.checks,
      hint: decision === 'allow'
        ? 'Agent may proceed without asking the human.'
        : 'Out of delegated scope or not executable — obtain human approval, have the human adjust the grant, or fix funding.',
    });
  });

// simulate: dry-run a transfer end to end (what would move, would it revert,
// remaining budget) WITHOUT broadcasting. The honest predictor for a
// realized-value account. Agent defaults to the loaded session key.
common(program.command('simulate'))
  .requiredOption('--account <addr>')
  .requiredOption('--token <addr>')
  .requiredOption('--to <addr>')
  .requiredOption('--amount <atomic>')
  .option('--agent <addr>', 'agent address (defaults to the loaded session key)')
  .action(async (o) => {
    const c = cfg(o);
    const acct = getAddress(o.account), token = getAddress(o.token), to = getAddress(o.to);
    const agentAddr = o.agent ? getAddress(o.agent) : agentAccount(o).address;
    const amount = BigInt(o.amount);
    const sim = await simulateSend(c, acct, token, to, amount, agentAddr);
    ok({ account: acct, agent: agentAddr, token, to, requested: amount, ...sim });
  });

// send: agent acts — capped transfer via a UserOp through the EntryPoint
common(program.command('send'))
  .requiredOption('--account <addr>')
  .requiredOption('--token <addr>')
  .requiredOption('--to <addr>')
  .requiredOption('--amount <atomic>')
  .option('--dry-run', 'simulate only; do not broadcast')
  .action(async (o) => {
    const c = cfg(o);
    const acct = getAddress(o.account), token = getAddress(o.token), to = getAddress(o.to);
    const amount = BigInt(o.amount);
    const agent = agentAccount(o);
    // The agent submits its OWN UserOp (acts as the bundler) so it never needs
    // the owner key — only its session key + a little ETH for base gas, which
    // the EntryPoint refunds to the beneficiary (the agent) below.
    const submitter = createWalletClient({ account: agent, chain: c.chain, transport: http(c.rpc) });

    // Preflight via a faithful simulation (mirrors on-chain enforcement incl.
    // perPeriod / balance / allowlist / expiry). Refuse BEFORE broadcasting so
    // no gas is spent on an op the contract would reject. --dry-run stops here.
    const sim = await simulateSend(c, acct, token, to, amount, agent.address);
    if (o.dryRun) ok({ dryRun: true, account: acct, agent: agent.address, token, to, requested: amount, ...sim });
    if (sim.decision === 'block') {
      const name = sim.predictedError ?? 'UnknownRevert';
      const isEscalate = ESCALATE_ERRORS.has(name);
      fail(isEscalate ? -32010 : -32012,
        isEscalate
          ? `Action refused (${name}): outside the agent delegated mandate.`
          : `Action would fail to execute (${name}).`,
        {
          decision: isEscalate ? 'escalate' : 'failed',
          predictedError: name, reasons: sim.reasons, cap: sim.cap, headroom: sim.headroom, checks: sim.checks,
          suggestion: isEscalate
            ? 'Get human approval or have the human adjust the grant (elytro-agent grant ...).'
            : 'Fix funding or the token issue; run `elytro-agent simulate` for detail. Not broadcast (no gas spent).',
        });
    }

    const innerCall = { target: token, value: 0n, data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [to, amount] }) };
    const callData = encodeFunctionData({ abi: ACCOUNT_ABI, functionName: 'executeUserOp', args: [[innerCall]] });
    const nonce = await c.pub.readContract({ address: c.entryPoint, abi: ENTRYPOINT_ABI, functionName: 'getNonce', args: [acct, 0n] });

    const op = {
      sender: acct, nonce, initCode: '0x' as Hex, callData,
      accountGasLimits: pack128(400000n, 400000n), preVerificationGas: 100000n,
      gasFees: pack128(1000000000n, (await legacyGas(c)) * 2n + 1000000000n),
      paymasterAndData: '0x' as Hex, signature: '0x' as Hex,
    };
    const userOpHash = await c.pub.readContract({ address: c.entryPoint, abi: ENTRYPOINT_ABI, functionName: 'getUserOpHash', args: [op] });
    op.signature = await agent.sign({ hash: userOpHash });

    const balBefore = await readBal(c, token, to);
    const hash = await submitter.writeContract({
      address: c.entryPoint, abi: ENTRYPOINT_ABI, functionName: 'handleOps',
      args: [[op], submitter.account!.address], gas: 2000000n, gasPrice: await legacyGas(c),
    });
    const r = await c.pub.waitForTransactionReceipt({ hash });
    const balAfter = await readBal(c, token, to);
    const moved = balAfter - balBefore;

    // handleOps mines successfully even when the inner UserOp reverts (the
    // EntryPoint catches inner reverts), so r.status is NOT the outcome. The
    // authoritative signal is UserOperationEvent.success for our userOpHash.
    const want = (userOpHash as Hex).toLowerCase();
    const opEvent = parseEventLogs({ abi: ENTRYPOINT_ABI, eventName: 'UserOperationEvent', logs: r.logs })
      .find((e) => (e.args.userOpHash as Hex).toLowerCase() === want);
    const opSuccess = opEvent ? Boolean(opEvent.args.success) : undefined;

    if (opSuccess === false) {
      // Decode WHY the contract refused, so the agent can branch deterministically.
      const reasonLog = parseEventLogs({ abi: ENTRYPOINT_ABI, eventName: 'UserOperationRevertReason', logs: r.logs })
        .find((e) => (e.args.userOpHash as Hex).toLowerCase() === want);
      const raw = reasonLog ? (reasonLog.args.revertReason as Hex) : undefined;
      const decoded = raw && raw !== '0x' ? decodeRevert(raw) : null;
      const name = decoded?.name ?? 'UnknownRevert';
      const isEscalate = ESCALATE_ERRORS.has(name);
      fail(isEscalate ? -32010 : -32012,
        isEscalate
          ? `Action refused on-chain (${name}): outside the agent delegated mandate.`
          : `Agent UserOp reverted on-chain (${name}).`,
        {
          decision: isEscalate ? 'escalate' : 'failed',
          reverted: { error: name, args: decoded?.args ?? [], raw: raw ?? null },
          txHash: hash, userOpHash, account: acct, agent: agent.address, token, to, requested: amount, moved,
          suggestion: isEscalate
            ? 'Get human approval or have the human adjust the grant (elytro-agent grant ...).'
            : 'The action failed to execute (funding or token behavior). Run `elytro-agent simulate` and inspect the error.',
        });
    }

    ok({
      status: r.status, userOpSuccess: opSuccess ?? null, txHash: hash, userOpHash,
      account: acct, agent: agent.address, token, to,
      requested: amount, moved, executed: opSuccess === true && moved === amount,
      note: opSuccess === undefined
        ? `Could not find UserOperationEvent in the receipt; verify on-chain (moved ${moved}).`
        : moved === amount
          ? 'Capped transfer executed autonomously within the human-delegated envelope.'
          : `UserOp succeeded on-chain but recipient delta (${moved}) differs from requested (${amount}); likely a fee-on-transfer or rebasing token.`,
    });
  });

// earn: agent buys the Cleave Earn (P / yield) leg via the Zap's yieldBuy,
// bounded by the SAME realized-value cap. The engine charges the account's
// measured USDC outflow even though a Uniswap router moves it (`transferFrom`
// under a standing owner-set allowance). Requires the owner to have, ONCE:
//   executeAsOwner([USDC.approve(zap, X)])  AND  setAllowedCall(agent, zap, yieldBuy).
// The agent never approves and never holds the owner key.
common(program.command('earn'))
  .description('Buy the Cleave Earn (P/yield) leg via the Zap, bounded by the realized-value USDC cap')
  .requiredOption('--account <addr>')
  .requiredOption('--amount <atomic>', 'USDC to spend (6 decimals)')
  .option('--zap <addr>', 'Cleave Zap', CLEAVE_ZAP)
  .option('--series <addr>', 'Cleave series', CLEAVE_SERIES)
  .option('--usdc <addr>', 'quote token', CLEAVE_USDC)
  .option('--pool-fee <fee>', 'USDC/P pool fee tier', '10000')
  .option('--min-out <atomic>', 'minimum P out (slippage floor)', '0')
  .option('--deadline <unix>', 'deadline (unix seconds)')
  .option('--dry-run', 'simulate only; do not broadcast')
  .action(async (o) => {
    const c = cfg(o);
    const acct = getAddress(o.account), zap = getAddress(o.zap), series = getAddress(o.series), usdc = getAddress(o.usdc);
    const amount = BigInt(o.amount), poolFee = Number(o.poolFee), minOut = BigInt(o.minOut);
    const deadline = o.deadline ? BigInt(o.deadline) : BigInt(Math.floor(Date.now() / 1000) + 600);
    const agent = agentAccount(o);
    const innerCall = {
      target: zap, value: 0n,
      data: encodeFunctionData({ abi: ZAP_ABI, functionName: 'yieldBuy', args: [series, poolFee, amount, minOut, deadline] }),
    };

    // Faithful preflight: eth_call the REAL agent path (allowlist + forbidden
    // surface + realized-value charge) AND the live Uniswap swap. It reverts
    // exactly as the contract would on-chain; viem decodes the custom error.
    const cap = await readCap(c, acct, agent.address, usdc);
    let predictedError: string | null = null;
    try {
      await c.pub.simulateContract({ address: acct, abi: SIM_ABI, functionName: 'executeAsAgent', args: [[innerCall]], account: agent.address });
    } catch (e) {
      const rev = (e as BaseError).walk?.((x) => x instanceof ContractFunctionRevertedError) as ContractFunctionRevertedError | undefined;
      predictedError = rev?.data?.errorName ?? rev?.reason ?? 'UnknownRevert';
    }
    const decision = predictedError ? 'block' : 'allow';
    const headroom = {
      perTx: cap.perTx === 0n ? null : cap.perTx,
      total: cap.total === 0n ? null : (cap.total > cap.spentTotal ? cap.total - cap.spentTotal : 0n),
    };

    if (decision === 'block') {
      const isEscalate = ESCALATE_ERRORS.has(predictedError!);
      if (o.dryRun) ok({ dryRun: true, decision, predictedError, account: acct, agent: agent.address, zap, series, usdc, willSpend: 0n, headroom });
      fail(isEscalate ? -32010 : -32012,
        isEscalate ? `Earn refused (${predictedError}): outside the agent delegated mandate.` : `Earn would fail to execute (${predictedError}).`,
        { decision: isEscalate ? 'escalate' : 'failed', predictedError, cap, headroom,
          suggestion: isEscalate
            ? 'Get human approval or have the human adjust the grant (elytro-agent grant ...).'
            : 'Check account USDC funding, the Zap allowance, or widen --min-out slippage. Not broadcast (no gas spent).' });
    }
    if (o.dryRun) ok({ dryRun: true, decision, predictedError: null, account: acct, agent: agent.address, zap, series, usdc, willSpend: amount, headroom });

    // Execute via the EntryPoint (same machinery as `send`): the agent signs its
    // own UserOp and submits it (acts as bundler), so it never needs the owner key.
    const pToken = await c.pub.readContract({ address: series, abi: SERIES_ABI, functionName: 'P' }) as Address;
    const usdcBefore = await readBal(c, usdc, acct);
    const pBefore = await readBal(c, pToken, acct);
    const callData = encodeFunctionData({ abi: ACCOUNT_ABI, functionName: 'executeUserOp', args: [[innerCall]] });
    const nonce = await c.pub.readContract({ address: c.entryPoint, abi: ENTRYPOINT_ABI, functionName: 'getNonce', args: [acct, 0n] });
    const op = {
      sender: acct, nonce, initCode: '0x' as Hex, callData,
      accountGasLimits: pack128(500000n, 1200000n), preVerificationGas: 100000n,
      gasFees: pack128(1000000000n, (await legacyGas(c)) * 2n + 1000000000n),
      paymasterAndData: '0x' as Hex, signature: '0x' as Hex,
    };
    const userOpHash = await c.pub.readContract({ address: c.entryPoint, abi: ENTRYPOINT_ABI, functionName: 'getUserOpHash', args: [op] });
    op.signature = await agent.sign({ hash: userOpHash });
    const submitter = createWalletClient({ account: agent, chain: c.chain, transport: http(c.rpc) });
    const hash = await submitter.writeContract({
      address: c.entryPoint, abi: ENTRYPOINT_ABI, functionName: 'handleOps',
      args: [[op], submitter.account!.address], gas: 3500000n, gasPrice: await legacyGas(c),
    });
    const r = await c.pub.waitForTransactionReceipt({ hash });
    const want = (userOpHash as Hex).toLowerCase();
    const opEvent = parseEventLogs({ abi: ENTRYPOINT_ABI, eventName: 'UserOperationEvent', logs: r.logs })
      .find((e) => (e.args.userOpHash as Hex).toLowerCase() === want);
    const opSuccess = opEvent ? Boolean(opEvent.args.success) : undefined;

    const usdcAfter = await readBal(c, usdc, acct);
    const pAfter = await readBal(c, pToken, acct);
    const usdcSpent = usdcBefore > usdcAfter ? usdcBefore - usdcAfter : 0n;
    const pReceived = pAfter > pBefore ? pAfter - pBefore : 0n;

    if (opSuccess === false) {
      const reasonLog = parseEventLogs({ abi: ENTRYPOINT_ABI, eventName: 'UserOperationRevertReason', logs: r.logs })
        .find((e) => (e.args.userOpHash as Hex).toLowerCase() === want);
      const raw = reasonLog ? (reasonLog.args.revertReason as Hex) : undefined;
      const decoded = raw && raw !== '0x' ? decodeRevert(raw) : null;
      const name = decoded?.name ?? 'UnknownRevert';
      const isEscalate = ESCALATE_ERRORS.has(name);
      fail(isEscalate ? -32010 : -32012,
        isEscalate ? `Earn refused on-chain (${name}): outside the agent delegated mandate.` : `Earn UserOp reverted on-chain (${name}).`,
        { decision: isEscalate ? 'escalate' : 'failed', reverted: { error: name, args: decoded?.args ?? [], raw: raw ?? null },
          txHash: hash, userOpHash, account: acct, agent: agent.address, zap, series, usdc, requested: amount, usdcSpent, pReceived,
          suggestion: isEscalate
            ? 'Get human approval or have the human adjust the grant (elytro-agent grant ...).'
            : 'Check funding/allowance/slippage; run `elytro-agent earn --dry-run` to inspect.' });
    }

    ok({
      status: r.status, userOpSuccess: opSuccess ?? null, txHash: hash, userOpHash,
      account: acct, agent: agent.address, zap, series, pToken, usdc,
      requested: amount, usdcSpent, pReceived,
      executed: opSuccess === true && usdcSpent > 0n && pReceived > 0n,
      note: opSuccess === undefined
        ? `Could not find UserOperationEvent; verify on-chain (USDC spent ${usdcSpent}, P received ${pReceived}).`
        : 'Earn (P) bought autonomously within the human-delegated realized-value cap; USDC outflow charged against the cap.',
    });
  });

// boost: agent buys the Cleave Boost (N / upside) leg via the Zap's boostFull,
// a PAYABLE native-ETH call (no approve needed). Bounded by the agent's native
// (address(0)) cap — the engine charges the measured ETH outflow (value − ethBack).
// Owner must, once: setAllowedCall(agent, zap, boostFull) AND setCap on native.
common(program.command('boost'))
  .description('Buy the Cleave Boost (N/upside) leg via the Zap, bounded by the realized-value native-ETH cap')
  .requiredOption('--account <addr>')
  .requiredOption('--amount <wei>', 'native ETH to spend (18 decimals)')
  .option('--zap <addr>', 'Cleave Zap', CLEAVE_ZAP)
  .option('--series <addr>', 'Cleave series', CLEAVE_SERIES)
  .option('--pool-fee <fee>', 'P/USDC pool fee tier', '10000')
  .option('--weth-fee <fee>', 'ETH/WETH-leg fee tier', '500')
  .option('--rounds <n>', 'leverage rounds', '12')
  .option('--min-out <atomic>', 'minimum N out (slippage floor)', '0')
  .option('--deadline <unix>', 'deadline (unix seconds)')
  .option('--dry-run', 'simulate only; do not broadcast')
  .action(async (o) => {
    const c = cfg(o);
    const acct = getAddress(o.account), zap = getAddress(o.zap), series = getAddress(o.series);
    const amount = BigInt(o.amount), poolFee = Number(o.poolFee), wethFee = Number(o.wethFee), rounds = BigInt(o.rounds), minOut = BigInt(o.minOut);
    const deadline = o.deadline ? BigInt(o.deadline) : BigInt(Math.floor(Date.now() / 1000) + 600);
    const agent = agentAccount(o);
    const innerCall = {
      target: zap, value: amount,
      data: encodeFunctionData({ abi: ZAP_ABI, functionName: 'boostFull', args: [series, poolFee, wethFee, rounds, minOut, deadline] }),
    };

    // Faithful preflight: eth_call the REAL agent path (allowlist + native-cap
    // realized-value charge) AND the live boost route. Reverts as on-chain would.
    const cap = await readCap(c, acct, agent.address, NATIVE_ASSET);
    let predictedError: string | null = null;
    try {
      await c.pub.simulateContract({ address: acct, abi: SIM_ABI, functionName: 'executeAsAgent', args: [[innerCall]], account: agent.address });
    } catch (e) {
      const rev = (e as BaseError).walk?.((x) => x instanceof ContractFunctionRevertedError) as ContractFunctionRevertedError | undefined;
      predictedError = rev?.data?.errorName ?? rev?.reason ?? 'UnknownRevert';
    }
    const decision = predictedError ? 'block' : 'allow';
    const headroom = {
      perTx: cap.perTx === 0n ? null : cap.perTx,
      total: cap.total === 0n ? null : (cap.total > cap.spentTotal ? cap.total - cap.spentTotal : 0n),
    };

    if (decision === 'block') {
      const isEscalate = ESCALATE_ERRORS.has(predictedError!);
      if (o.dryRun) ok({ dryRun: true, decision, predictedError, account: acct, agent: agent.address, zap, series, willSpend: 0n, headroom });
      fail(isEscalate ? -32010 : -32012,
        isEscalate ? `Boost refused (${predictedError}): outside the agent delegated mandate.` : `Boost would fail to execute (${predictedError}).`,
        { decision: isEscalate ? 'escalate' : 'failed', predictedError, cap, headroom,
          suggestion: isEscalate
            ? 'Get human approval or have the human adjust the native-ETH grant (setCap on address(0)).'
            : 'Check account ETH funding or widen --min-out slippage. Not broadcast (no gas spent).' });
    }
    if (o.dryRun) ok({ dryRun: true, decision, predictedError: null, account: acct, agent: agent.address, zap, series, willSpend: amount, headroom });

    // Execute via the EntryPoint, same path as `send`/`earn`.
    const nToken = await c.pub.readContract({ address: series, abi: SERIES_ABI, functionName: 'N' }) as Address;
    const nBefore = await readBal(c, nToken, acct);
    const spentBefore = (await readCap(c, acct, agent.address, NATIVE_ASSET)).spentTotal;
    const callData = encodeFunctionData({ abi: ACCOUNT_ABI, functionName: 'executeUserOp', args: [[innerCall]] });
    const nonce = await c.pub.readContract({ address: c.entryPoint, abi: ENTRYPOINT_ABI, functionName: 'getNonce', args: [acct, 0n] });
    const op = {
      sender: acct, nonce, initCode: '0x' as Hex, callData,
      accountGasLimits: pack128(600000n, 4000000n), preVerificationGas: 200000n,
      gasFees: pack128(1000000000n, (await legacyGas(c)) * 2n + 1000000000n),
      paymasterAndData: '0x' as Hex, signature: '0x' as Hex,
    };
    const userOpHash = await c.pub.readContract({ address: c.entryPoint, abi: ENTRYPOINT_ABI, functionName: 'getUserOpHash', args: [op] });
    op.signature = await agent.sign({ hash: userOpHash });
    const submitter = createWalletClient({ account: agent, chain: c.chain, transport: http(c.rpc) });
    const hash = await submitter.writeContract({
      address: c.entryPoint, abi: ENTRYPOINT_ABI, functionName: 'handleOps',
      args: [[op], submitter.account!.address], gas: 7000000n, gasPrice: await legacyGas(c),
    });
    const r = await c.pub.waitForTransactionReceipt({ hash });
    const want = (userOpHash as Hex).toLowerCase();
    const opEvent = parseEventLogs({ abi: ENTRYPOINT_ABI, eventName: 'UserOperationEvent', logs: r.logs })
      .find((e) => (e.args.userOpHash as Hex).toLowerCase() === want);
    const opSuccess = opEvent ? Boolean(opEvent.args.success) : undefined;

    const nAfter = await readBal(c, nToken, acct);
    const spentAfter = (await readCap(c, acct, agent.address, NATIVE_ASSET)).spentTotal;
    const ethSpent = spentAfter > spentBefore ? spentAfter - spentBefore : 0n; // realized native outflow charged to the cap
    const nReceived = nAfter > nBefore ? nAfter - nBefore : 0n;

    if (opSuccess === false) {
      const reasonLog = parseEventLogs({ abi: ENTRYPOINT_ABI, eventName: 'UserOperationRevertReason', logs: r.logs })
        .find((e) => (e.args.userOpHash as Hex).toLowerCase() === want);
      const raw = reasonLog ? (reasonLog.args.revertReason as Hex) : undefined;
      const decoded = raw && raw !== '0x' ? decodeRevert(raw) : null;
      const name = decoded?.name ?? 'UnknownRevert';
      const isEscalate = ESCALATE_ERRORS.has(name);
      fail(isEscalate ? -32010 : -32012,
        isEscalate ? `Boost refused on-chain (${name}): outside the agent delegated mandate.` : `Boost UserOp reverted on-chain (${name}).`,
        { decision: isEscalate ? 'escalate' : 'failed', reverted: { error: name, args: decoded?.args ?? [], raw: raw ?? null },
          txHash: hash, userOpHash, account: acct, agent: agent.address, zap, series, requested: amount, ethSpent, nReceived,
          suggestion: isEscalate
            ? 'Get human approval or have the human adjust the native-ETH grant (setCap on address(0)).'
            : 'Check funding/slippage; run `elytro-agent boost --dry-run` to inspect.' });
    }

    ok({
      status: r.status, userOpSuccess: opSuccess ?? null, txHash: hash, userOpHash,
      account: acct, agent: agent.address, zap, series, nToken,
      requested: amount, ethSpent, nReceived,
      executed: opSuccess === true && ethSpent > 0n && nReceived > 0n,
      note: opSuccess === undefined
        ? `Could not find UserOperationEvent; verify on-chain (ETH spent ${ethSpent}, N received ${nReceived}).`
        : 'Boost (N) bought autonomously within the human-delegated native-ETH cap; ETH outflow charged against the cap.',
    });
  });

// status: account + agent + balances
common(program.command('status'))
  .requiredOption('--account <addr>')
  .option('--agent <addr>')
  .option('--token <addr>')
  .action(async (o) => {
    const c = cfg(o);
    const acct = getAddress(o.account);
    const owner = await c.pub.readContract({ address: acct, abi: ACCOUNT_ABI, functionName: 'owner' });
    const out: Record<string, unknown> = { account: acct, owner };
    if (o.agent && o.token) {
      const cap = await readCap(c, acct, getAddress(o.agent), getAddress(o.token));
      out.cap = cap;
    }
    if (o.token) out.accountTokenBalance = await readBal(c, getAddress(o.token), acct);
    ok(out);
  });

async function readCap(c: ReturnType<typeof cfg>, account: Address, agent: Address, token: Address) {
  return (await c.pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: 'getCap', args: [agent, token] })) as {
    set: boolean; perTx: bigint; perPeriod: bigint; period: bigint; total: bigint; spentPeriod: bigint; periodStart: number; spentTotal: bigint;
  };
}
async function readBal(c: ReturnType<typeof cfg>, token: Address, who: Address) {
  return (await c.pub.readContract({ address: token, abi: ERC20_ABI, functionName: 'balanceOf', args: [who] })) as bigint;
}

/// Faithful off-chain simulation of an agent `transfer` of a protected token,
/// backed by real on-chain state + a real eth_call of the transfer. Mirrors the
/// exact revert order of _execAsAgent + _charge so the predicted error matches
/// what the contract would actually throw — closing the gaps the pure-arithmetic
/// `check` missed (perPeriod window, account balance, allowlist, expiry).
async function simulateSend(
  c: ReturnType<typeof cfg>, acct: Address, token: Address, to: Address | undefined, amount: bigint, agentAddr: Address,
) {
  const [cap, agentTuple, allowlisted, protectedFlag, accountBal, block] = await Promise.all([
    readCap(c, acct, agentAddr, token),
    c.pub.readContract({ address: acct, abi: ACCOUNT_ABI, functionName: 'agents', args: [agentAddr] }) as Promise<readonly [boolean, number, number]>,
    c.pub.readContract({ address: acct, abi: ACCOUNT_ABI, functionName: 'allowedCall', args: [agentAddr, token, TRANSFER_SELECTOR] }) as Promise<boolean>,
    c.pub.readContract({ address: acct, abi: ACCOUNT_ABI, functionName: 'isProtected', args: [token] }) as Promise<boolean>,
    readBal(c, token, acct),
    c.pub.getBlock(),
  ]);
  const now = BigInt(block.timestamp);
  const [active, notBefore, expiresAt] = agentTuple;

  // Real token-level check: would the transfer itself succeed from the account?
  // Catches paused/blacklist/non-standard reverts that arithmetic cannot see.
  // Skipped when no recipient is given (a recipient-less `check` preflight).
  let transferOk = true;
  let transferRevert: string | null = null;
  if (to) {
    try {
      await c.pub.call({ account: acct, to: token, data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [to, amount] }) });
    } catch (e) {
      transferOk = false;
      transferRevert = (e as Error).message?.split('\n')[0] ?? String(e);
    }
  }

  // Replicate the rolling-window reset _charge applies before the perPeriod test.
  const windowElapsed = cap.period !== 0n && now >= BigInt(cap.periodStart) + cap.period;
  const effSpentPeriod = windowElapsed ? 0n : cap.spentPeriod;

  // First blocker, in on-chain revert order. The predicted outflow for a plain
  // ERC-20 transfer is `amount`; the contract charges the realized balance-delta,
  // which equals `amount` for a standard token (fee-on-transfer would differ).
  let error: string | null = null;
  const reasons: string[] = [];
  const add = (err: string, msg: string) => {
    if (!error) error = err;
    reasons.push(msg);
  };

  if (!active) add('AgentInactive', 'agent is not active for this account');
  else {
    if (now < BigInt(notBefore)) add('AgentNotYetValid', `agent not valid until unix ${notBefore}`);
    if (now > BigInt(expiresAt)) add('AgentExpired', `agent grant expired at unix ${expiresAt}`);
  }
  if (!allowlisted) add('CallNotAllowlisted', 'transfer is not allowlisted for (agent, token)');
  if (!protectedFlag) add('UnprotectedTokenTransfer', 'token is not in the protected (measured) set');
  if (accountBal < amount) add('CallFailed', `account balance ${accountBal} < amount ${amount} (transfer would revert)`);
  else if (!transferOk) add('CallFailed', `token transfer would revert: ${transferRevert}`);
  if (!cap.set) add('UncappedProtectedAssetMoved', 'no cap set for (agent, token)');
  else {
    if (cap.perTx !== 0n && amount > cap.perTx) add('PerTxCapExceeded', `amount ${amount} exceeds per-tx cap ${cap.perTx}`);
    if (cap.period !== 0n && cap.perPeriod !== 0n && effSpentPeriod + amount > cap.perPeriod)
      add('PerPeriodCapExceeded', `would exceed per-period cap ${cap.perPeriod} (spent ${effSpentPeriod} this window)`);
    if (cap.total !== 0n && cap.spentTotal + amount > cap.total)
      add('TotalCapExceeded', `would exceed total cap ${cap.total} (spent ${cap.spentTotal})`);
  }

  const headroom = {
    perTx: cap.perTx === 0n ? null : cap.perTx,
    perPeriod: cap.period === 0n || cap.perPeriod === 0n ? null : (cap.perPeriod > effSpentPeriod ? cap.perPeriod - effSpentPeriod : 0n),
    total: cap.total === 0n ? null : (cap.total > cap.spentTotal ? cap.total - cap.spentTotal : 0n),
  };

  const decision = error ? 'block' : 'allow';
  return {
    decision, predictedError: error,
    willMove: decision === 'allow' ? amount : 0n,
    reasons: reasons.length ? reasons : ['within delegated envelope and executable'],
    checks: { agentActive: active, notBefore, expiresAt, allowlisted, protected: protectedFlag, accountBalance: accountBal, transferSimulated: Boolean(to), transferCallOk: transferOk, transferRevert },
    cap: { set: cap.set, perTx: cap.perTx, perPeriod: cap.perPeriod, period: cap.period, total: cap.total, spentPeriod: cap.spentPeriod, effectiveSpentPeriod: effSpentPeriod, periodStart: cap.periodStart, spentTotal: cap.spentTotal },
    headroom,
  };
}

// keygen: generate + store this agent's session key (run once). The human
// grants a cap to the printed address; the owner key is never involved.
program
  .command('keygen')
  .description('Generate and store the agent session key (run once)')
  .option('--force', 'overwrite an existing key')
  .action((o: { force?: boolean }) => {
    if (existsSync(KEY_FILE) && !o.force) {
      const addr = privateKeyToAccount(readFileSync(KEY_FILE, 'utf8').trim() as Hex).address;
      ok({ status: 'exists', agent: addr, keyFile: KEY_FILE, hint: 'Key already exists. Use --force to regenerate.' });
    }
    const pk = generatePrivateKey();
    mkdirSync(KEY_DIR, { recursive: true });
    writeFileSync(KEY_FILE, pk, { mode: 0o600 });
    chmodSync(KEY_FILE, 0o600);
    const addr = privateKeyToAccount(pk).address;
    ok({
      status: 'created',
      agent: addr,
      keyFile: KEY_FILE,
      hint: `Give this agent address to the human (owner) to delegate a cap: elytro-agent grant --agent ${addr} --token <addr> --per-tx <atomic> --total <atomic>`,
    });
  });

// whoami: print this agent's address (what the human grants a cap to).
program
  .command('whoami')
  .option('--agent-key <hex>')
  .action((o: Record<string, string | undefined>) => {
    ok({ agent: agentAccount(o).address });
  });

program.parseAsync().catch((e) => fail(-32000, (e as Error).message?.split('\n')[0] ?? String(e)));
