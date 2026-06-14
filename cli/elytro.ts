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
// Errors that mean "the agent hit its delegated ceiling" → escalate to human.
const CAP_ERRORS = new Set(['PerTxCapExceeded', 'PerPeriodCapExceeded', 'TotalCapExceeded', 'UncappedProtectedAssetMoved']);
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

// check: would this action be authorized? (off-chain preflight)
common(program.command('check'))
  .requiredOption('--account <addr>')
  .requiredOption('--agent <addr>')
  .requiredOption('--token <addr>')
  .requiredOption('--amount <atomic>')
  .action(async (o) => {
    const c = cfg(o);
    const cap = await readCap(c, getAddress(o.account), getAddress(o.agent), getAddress(o.token));
    const amount = BigInt(o.amount);
    const reasons: string[] = [];
    if (!cap.set) reasons.push('no cap for (agent, token)');
    if (cap.perTx !== 0n && amount > cap.perTx) reasons.push(`amount ${amount} exceeds per-tx cap ${cap.perTx}`);
    if (cap.total !== 0n && cap.spentTotal + amount > cap.total) reasons.push(`would exceed total cap ${cap.total} (spent ${cap.spentTotal})`);
    const decision = reasons.length ? 'escalate' : 'allow';
    ok({
      decision, reasons: reasons.length ? reasons : ['within delegated envelope'],
      cap: { perTx: cap.perTx, total: cap.total, spentTotal: cap.spentTotal },
      hint: decision === 'allow' ? 'Agent may proceed without asking the human.' : 'Out of delegated scope — obtain human approval or have the human raise the grant.',
    });
  });

// send: agent acts — capped transfer via a UserOp through the EntryPoint
common(program.command('send'))
  .requiredOption('--account <addr>')
  .requiredOption('--token <addr>')
  .requiredOption('--to <addr>')
  .requiredOption('--amount <atomic>')
  .action(async (o) => {
    const c = cfg(o);
    const acct = getAddress(o.account), token = getAddress(o.token), to = getAddress(o.to);
    const amount = BigInt(o.amount);
    const agent = agentAccount(o);
    // The agent submits its OWN UserOp (acts as the bundler) so it never needs
    // the owner key — only its session key + a little ETH for base gas, which
    // the EntryPoint refunds to the beneficiary (the agent) below.
    const submitter = createWalletClient({ account: agent, chain: c.chain, transport: http(c.rpc) });

    // preflight against the on-chain cap
    const cap = await readCap(c, acct, agent.address, token);
    if (!cap.set || (cap.perTx !== 0n && amount > cap.perTx) || (cap.total !== 0n && cap.spentTotal + amount > cap.total))
      fail(-32010, 'Action is outside the agent delegated mandate.', {
        decision: 'escalate', cap: { perTx: cap.perTx, total: cap.total, spentTotal: cap.spentTotal },
        suggestion: 'Run `elytro-agent check` for detail, then get human approval or a larger grant.',
      });

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
      const isCap = CAP_ERRORS.has(name);
      fail(isCap ? -32010 : -32012,
        isCap
          ? 'Action refused on-chain: outside the agent delegated mandate.'
          : `Agent UserOp reverted on-chain (${name}).`,
        {
          decision: isCap ? 'escalate' : 'failed',
          reverted: { error: name, args: decoded?.args ?? [], raw: raw ?? null },
          txHash: hash, userOpHash, account: acct, agent: agent.address, token, to, requested: amount, moved,
          suggestion: isCap
            ? 'Get human approval or have the human raise the grant (elytro-agent grant ...).'
            : 'The action is not permitted as constructed (allowlist, balance, expiry, or token behavior). Run `elytro-agent check` and inspect the error.',
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
