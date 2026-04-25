"""
Smart Contract Weakness Classification (SWC) Registry.
Thay thế mitre_reference.py trong Hướng B — cùng pattern, đổi data source.

Source: https://swcregistry.io (40 entries) + DeFi-specific attack patterns
"""

from typing import Dict, List, Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.contract_models import ContractEntity


# ─── SWC Registry (40 entries) ────────────────────────────────────────────────

SWC_REGISTRY: Dict[str, Dict[str, Any]] = {
    "SWC-100": {
        "name": "Function Default Visibility",
        "description": "Functions without explicit visibility specifier default to public, "
                       "allowing unintended external access.",
        "category": "access_control",
        "domains": ["appsec", "blockchain"],
        "severity": "medium",
        "example_pattern": "function transfer() { ... }  // missing visibility → defaults to public",
        "mitigation": "Always declare function visibility explicitly (public/private/internal/external).",
        "offensive_notes": "Scan for functions without visibility — call privileged internal functions directly.",
        "defensive_notes": "Linter enforcement (Solhint rule: func-visibility). Code review checklist.",
        "auditor_notes": "Flag all functions without explicit visibility. Medium priority in audit.",
        "known_exploits": [],
    },
    "SWC-101": {
        "name": "Integer Overflow and Underflow",
        "description": "Arithmetic operations without bounds checking lead to integer wrap-around, "
                       "allowing attackers to manipulate balances or bypass checks.",
        "category": "arithmetic",
        "domains": ["cryptography", "appsec"],
        "severity": "high",
        "example_pattern": "uint8 x = 255; x += 1;  // wraps to 0",
        "mitigation": "Use Solidity 0.8+ (auto-revert on overflow) or SafeMath library for 0.7 and below.",
        "offensive_notes": "Find arithmetic operations on token amounts — trigger overflow to mint tokens or drain balances.",
        "defensive_notes": "Migrate to Solidity ≥0.8.0. Use SafeMath for legacy code. Add invariant checks.",
        "auditor_notes": "Check compiler version. If < 0.8.0, verify SafeMath usage on all arithmetic.",
        "known_exploits": ["BEC Token hack 2018 — $900M", "SMT Token 2018 — $64M"],
    },
    "SWC-102": {
        "name": "Outdated Compiler Version",
        "description": "Using old compiler versions may expose contracts to known bugs and missing security features.",
        "category": "logic_error",
        "domains": ["blockchain", "appsec"],
        "severity": "low",
        "example_pattern": "pragma solidity ^0.4.0;  // extremely old",
        "mitigation": "Use a recent stable compiler version (≥0.8.x). Avoid floating pragmas (^).",
        "offensive_notes": "Old versions may have known compiler bugs; research version-specific vulnerabilities.",
        "defensive_notes": "Pin pragma to exact version. Use latest stable release.",
        "auditor_notes": "Always report compiler version. Flag anything below 0.8.0 as medium+.",
        "known_exploits": [],
    },
    "SWC-103": {
        "name": "Floating Pragma",
        "description": "Contracts use floating pragma (^) which may compile with a different compiler "
                       "version than intended, introducing unexpected behavior.",
        "category": "logic_error",
        "domains": ["blockchain"],
        "severity": "low",
        "example_pattern": "pragma solidity ^0.8.0;  // allows 0.8.x where x could be newer buggy version",
        "mitigation": "Use exact pragma: pragma solidity 0.8.19;",
        "offensive_notes": "Low direct impact but increases attack surface via compiler version confusion.",
        "defensive_notes": "CI/CD should enforce exact pragma. Slither rule: pragma.",
        "auditor_notes": "Note floating pragma as informational unless combined with old version.",
        "known_exploits": [],
    },
    "SWC-104": {
        "name": "Unchecked Call Return Value",
        "description": "The return value of low-level calls (send, call, delegatecall) is not checked, "
                       "allowing silent failures that leave contract in inconsistent state.",
        "category": "unchecked_calls",
        "domains": ["appsec", "blockchain"],
        "severity": "medium",
        "example_pattern": "addr.send(amount);  // return value ignored — failure is silent",
        "mitigation": "Always check return values: require(addr.send(amount)). Prefer transfer() or call() with checks.",
        "offensive_notes": "Silent send failure can cause inconsistent accounting — exploit state divergence.",
        "defensive_notes": "Use OpenZeppelin Address.sendValue(). Add explicit require on send/call.",
        "auditor_notes": "Search for all .send() and low-level .call() — verify return value handling.",
        "known_exploits": ["King of the Ether Throne — loss of funds"],
    },
    "SWC-105": {
        "name": "Unprotected Ether Withdrawal",
        "description": "A function that sends Ether lacks access control, allowing any caller to drain funds.",
        "category": "access_control",
        "domains": ["appsec", "blockchain"],
        "severity": "critical",
        "example_pattern": "function withdraw() public { msg.sender.transfer(address(this).balance); }",
        "mitigation": "Add onlyOwner or role-based access control to withdrawal functions.",
        "offensive_notes": "Directly call withdraw() to drain contract balance immediately.",
        "defensive_notes": "All fund-withdrawing functions must have explicit access control.",
        "auditor_notes": "Highest priority finding. Search for transfer/send/call{value} without modifiers.",
        "known_exploits": ["Multiple DeFi projects — fund drain via unprotected withdraw"],
    },
    "SWC-106": {
        "name": "Unprotected SELFDESTRUCT Instruction",
        "description": "A selfdestruct call is not protected by access control, allowing any attacker to "
                       "destroy the contract and steal all Ether.",
        "category": "access_control",
        "domains": ["appsec", "blockchain"],
        "severity": "critical",
        "example_pattern": "function kill() public { selfdestruct(msg.sender); }",
        "mitigation": "Restrict selfdestruct to owner. Consider removing selfdestruct entirely.",
        "offensive_notes": "Find unprotected selfdestruct → drain all ETH and destroy contract.",
        "defensive_notes": "Avoid selfdestruct in production contracts. If needed, add multi-sig control.",
        "auditor_notes": "Search for selfdestruct keyword — highest severity if unprotected.",
        "known_exploits": ["Parity Multisig Wallet 2017 — $30M frozen"],
    },
    "SWC-107": {
        "name": "Reentrancy",
        "description": "A function makes an external call before updating state, allowing a malicious "
                       "contract to re-enter and execute the function multiple times.",
        "category": "reentrancy",
        "domains": ["appsec", "blockchain"],
        "severity": "critical",
        "example_pattern": "msg.sender.call{value: amount}(''); balances[msg.sender] -= amount;  // state AFTER call",
        "mitigation": "Checks-Effects-Interactions pattern: update state BEFORE external call. "
                      "Add OpenZeppelin ReentrancyGuard modifier.",
        "offensive_notes": "Deploy malicious contract with fallback function that calls victim's withdraw(). "
                           "Each re-entry drains more ETH before balance is decremented.",
        "defensive_notes": "Apply CEI pattern strictly. Add nonReentrant modifier to all fund-moving functions.",
        "auditor_notes": "Search for external calls followed by state updates. Check for ReentrancyGuard. "
                         "Prioritize functions that send ETH.",
        "known_exploits": ["The DAO 2016 — $60M", "Cream Finance 2021 — $130M",
                           "Fei Protocol 2022 — $80M", "Euler Finance 2023 — $197M"],
    },
    "SWC-108": {
        "name": "State Variable Default Visibility",
        "description": "State variables without explicit visibility default to internal, "
                       "which may not match developer intent.",
        "category": "access_control",
        "domains": ["appsec"],
        "severity": "low",
        "example_pattern": "uint256 secretKey;  // defaults to internal, not private",
        "mitigation": "Always declare state variable visibility explicitly.",
        "offensive_notes": "Internal vars can still be read from blockchain storage (slots are public).",
        "defensive_notes": "Use private for sensitive data. Educate team that private ≠ unreadable on-chain.",
        "auditor_notes": "Flag missing visibility on state vars. Educate on on-chain transparency.",
        "known_exploits": [],
    },
    "SWC-109": {
        "name": "Uninitialized Storage Pointer",
        "description": "Uninitialized local storage variables can overwrite critical contract storage slots.",
        "category": "logic_error",
        "domains": ["blockchain", "appsec"],
        "severity": "high",
        "example_pattern": "function f() public { MyStruct s; s.owner = msg.sender; }  // writes to slot 0",
        "mitigation": "Use memory keyword explicitly for local struct variables in Solidity <0.5.0. "
                      "Upgrade to ≥0.5.0 where storage pointers must be initialized.",
        "offensive_notes": "Manipulate uninitialized storage to overwrite owner slot or other critical vars.",
        "defensive_notes": "Compiler ≥0.5.0 eliminates this. For legacy, always specify memory/storage.",
        "auditor_notes": "Only relevant for Solidity <0.5.0. Historical but still appears in old contracts.",
        "known_exploits": ["Honey Pot contracts using storage confusion"],
    },
    "SWC-110": {
        "name": "Assert Violation",
        "description": "assert() should only be used for invariants, not input validation. "
                       "Misuse can trap ETH permanently.",
        "category": "logic_error",
        "domains": ["appsec"],
        "severity": "medium",
        "example_pattern": "assert(msg.value > 0);  // should be require()",
        "mitigation": "Use require() for input validation. Use assert() only for internal invariant checks.",
        "offensive_notes": "Assert failure consumes all gas (pre-0.8) vs revert. Useful for DoS.",
        "defensive_notes": "Code review for assert() usage. Replace with require() for user-facing checks.",
        "auditor_notes": "Flag every assert() — verify it is a true invariant, not input validation.",
        "known_exploits": [],
    },
    "SWC-111": {
        "name": "Use of Deprecated Solidity Functions",
        "description": "Deprecated functions (suicide, throw, sha3, callcode) may behave unexpectedly.",
        "category": "logic_error",
        "domains": ["blockchain"],
        "severity": "low",
        "example_pattern": "suicide(owner);  // deprecated alias for selfdestruct",
        "mitigation": "Replace with current equivalents: selfdestruct, revert, keccak256, delegatecall.",
        "offensive_notes": "Low impact but signal poor code quality / lack of security review.",
        "defensive_notes": "Automated linting catches deprecated functions.",
        "auditor_notes": "Flag deprecated functions. Low severity but counts against code quality score.",
        "known_exploits": [],
    },
    "SWC-112": {
        "name": "Delegatecall to Untrusted Callee",
        "description": "delegatecall to an address controlled by user input allows attackers to execute "
                       "arbitrary code in the context of the calling contract.",
        "category": "access_control",
        "domains": ["appsec", "blockchain"],
        "severity": "critical",
        "example_pattern": "address(target).delegatecall(data);  // target from user input",
        "mitigation": "Never delegatecall to user-supplied addresses. Use whitelist of trusted implementations.",
        "offensive_notes": "Supply malicious contract address → delegatecall executes attacker code "
                           "with victim's storage and ETH.",
        "defensive_notes": "Audit all delegatecall usage. Proxy upgrades must use trusted admin.",
        "auditor_notes": "Critical finding if target is from user input. Also check proxy upgrade paths.",
        "known_exploits": ["Parity Multisig Library 2017 — $30M", "Wormhole 2022 — $320M"],
    },
    "SWC-113": {
        "name": "DoS with Failed Call",
        "description": "A contract loop or call that can be made to fail by an external actor, "
                       "causing the entire transaction to revert and blocking contract functionality.",
        "category": "denial_of_service",
        "domains": ["appsec", "blockchain"],
        "severity": "medium",
        "example_pattern": "for (uint i = 0; i < users.length; i++) { users[i].transfer(share); }  // one revert blocks all",
        "mitigation": "Pull-over-push payment pattern. Separate fund distribution from business logic.",
        "offensive_notes": "Make one address in a distribution loop revert → block all payouts permanently.",
        "defensive_notes": "Replace push payments with pull (claimable balances). Limit loop sizes.",
        "auditor_notes": "Find loops with external calls. Check if any single element can block the loop.",
        "known_exploits": ["GovernMental Ponzi — ETH trapped by failed send"],
    },
    "SWC-114": {
        "name": "Transaction Order Dependence",
        "description": "Contract behavior depends on transaction order (front-running), allowing miners "
                       "or MEV bots to manipulate outcomes.",
        "category": "front_running",
        "domains": ["defi", "blockchain"],
        "severity": "medium",
        "example_pattern": "approve() then transferFrom() — approve amount can be front-run",
        "mitigation": "Use commit-reveal scheme. EIP-2612 permit() for approvals. Slippage controls on AMMs.",
        "offensive_notes": "Monitor mempool for profitable transactions. Front-run approve → steal approved amount.",
        "defensive_notes": "Add deadline + slippage parameters. Use private mempool for sensitive ops.",
        "auditor_notes": "Analyze token approval flows. Check AMM interactions for slippage protection.",
        "known_exploits": ["ERC20 approve front-running (known theoretical)", "Various AMM sandwich attacks"],
    },
    "SWC-115": {
        "name": "Authorization through tx.origin",
        "description": "tx.origin returns the original transaction sender, not the immediate caller. "
                       "A phishing contract can trigger victim's contract as tx.origin.",
        "category": "access_control",
        "domains": ["appsec"],
        "severity": "high",
        "example_pattern": "require(tx.origin == owner);  // phishing contract bypasses check",
        "mitigation": "Use msg.sender instead of tx.origin for authorization.",
        "offensive_notes": "Deploy phishing contract that tricks owner into calling it. "
                           "Phishing contract then calls victim with owner's tx.origin.",
        "defensive_notes": "Replace all tx.origin with msg.sender. Slither rule: tx-origin.",
        "auditor_notes": "Search for tx.origin in require/if conditions. Always high severity.",
        "known_exploits": [],
    },
    "SWC-116": {
        "name": "Block values as a proxy for time",
        "description": "block.timestamp and block.number can be manipulated by miners within a ~15 second "
                       "window, affecting time-dependent logic.",
        "category": "timestamp",
        "domains": ["blockchain"],
        "severity": "low",
        "example_pattern": "require(block.timestamp >= endTime);  // miner can manipulate slightly",
        "mitigation": "Don't use block.timestamp for security-critical decisions. "
                      "For time locks, the ~15s variance is acceptable; for randomness, use VRF.",
        "offensive_notes": "Miner can adjust timestamp ±15s to be within or outside conditions.",
        "defensive_notes": "Acceptable for coarse time checks (days). Unacceptable for lottery randomness.",
        "auditor_notes": "Flag block.timestamp in conditions. Severity depends on precision required.",
        "known_exploits": ["Various lottery contracts manipulated by miners"],
    },
    "SWC-120": {
        "name": "Weak Sources of Randomness from Chain Attributes",
        "description": "Using block.timestamp, blockhash, or other on-chain attributes as randomness "
                       "sources can be predicted or manipulated by miners.",
        "category": "randomness",
        "domains": ["cryptography", "blockchain"],
        "severity": "high",
        "example_pattern": "uint rand = uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));",
        "mitigation": "Use Chainlink VRF for verifiable randomness. Commit-reveal schemes for games.",
        "offensive_notes": "Miners can choose blockhash to win lottery. Predict next block for gambling.",
        "defensive_notes": "Integrate Chainlink VRF. For commit-reveal, ensure timeout mechanism.",
        "auditor_notes": "Flag all PRNG using block attributes. Critical in lottery, NFT minting, gaming.",
        "known_exploits": ["SmartBillions lottery — manipulated by miner colluder"],
    },
    "SWC-121": {
        "name": "Missing Protection against Signature Replay Attacks",
        "description": "Signed messages can be replayed on same or different contracts/chains "
                       "without nonce or chainId binding.",
        "category": "access_control",
        "domains": ["cryptography", "appsec"],
        "severity": "high",
        "example_pattern": "ecrecover(hash, v, r, s);  // no nonce, no chainId — replayable",
        "mitigation": "Include nonce + chainId in signed message. Use EIP-712 structured hashing.",
        "offensive_notes": "Capture valid signature → replay to drain all approved funds repeatedly.",
        "defensive_notes": "Use EIP-712 with nonce mapping. Invalidate nonces on use.",
        "auditor_notes": "Find ecrecover calls — check for nonce and chainId binding.",
        "known_exploits": ["Ronin Bridge 2022 — $625M (validator replay)"],
    },
    "SWC-122": {
        "name": "Lack of Proper Signature Verification",
        "description": "Signature verification is missing or flawed, allowing unauthorized actions.",
        "category": "access_control",
        "domains": ["cryptography", "appsec"],
        "severity": "critical",
        "example_pattern": "require(signer == address(0) || signer == owner);  // accepts zero address",
        "mitigation": "Verify ecrecover result ≠ address(0). Check signer against whitelist.",
        "offensive_notes": "Send malformed signature → ecrecover returns address(0) → pass zero address check.",
        "defensive_notes": "Always check ecrecover result ≠ address(0). Use OpenZeppelin ECDSA library.",
        "auditor_notes": "Find all signature verification paths — test with malformed inputs.",
        "known_exploits": ["Multiple bridge hacks via signature verification bypass"],
    },
    "SWC-123": {
        "name": "Requirement Violation",
        "description": "Violation of preconditions (require) that should always hold, "
                       "indicating logic errors in the contract.",
        "category": "logic_error",
        "domains": ["appsec"],
        "severity": "medium",
        "example_pattern": "require(balances[msg.sender] >= amount);  // but balance can underflow elsewhere",
        "mitigation": "Audit all require conditions. Formal verification for critical invariants.",
        "offensive_notes": "Find paths where require can be bypassed through state manipulation.",
        "defensive_notes": "Add comprehensive test suite. Fuzzing to find require violations.",
        "auditor_notes": "Trace all code paths leading to require statements.",
        "known_exploits": [],
    },
    "SWC-124": {
        "name": "Write to Arbitrary Storage Location",
        "description": "User-controlled data can be written to arbitrary storage slots, "
                       "overwriting critical contract variables.",
        "category": "access_control",
        "domains": ["appsec", "blockchain"],
        "severity": "critical",
        "example_pattern": "function write(uint slot, uint val) public { assembly { sstore(slot, val) } }",
        "mitigation": "Never allow user input to control storage slot in sstore. "
                      "Audit all assembly blocks.",
        "offensive_notes": "Write to slot 0 (typically owner) to take over contract.",
        "defensive_notes": "Remove arbitrary sstore. Audit all inline assembly.",
        "auditor_notes": "Search for assembly sstore with user-controlled slot. Critical.",
        "known_exploits": ["Various proxy storage collisions"],
    },
    "SWC-125": {
        "name": "Incorrect Inheritance Order",
        "description": "Solidity uses C3 linearization for multiple inheritance. Wrong order causes "
                       "unexpected function resolution, often bypassing security checks.",
        "category": "logic_error",
        "domains": ["appsec", "blockchain"],
        "severity": "medium",
        "example_pattern": "contract Token is Ownable, ERC20 { }  // vs contract Token is ERC20, Ownable",
        "mitigation": "Follow Solidity docs on inheritance order. Test all inherited function paths.",
        "offensive_notes": "Exploit unexpected function resolution from wrong inheritance order.",
        "defensive_notes": "Careful code review for multiple inheritance. Test modifier application.",
        "auditor_notes": "Check multiple inheritance contracts. Verify MRO matches intent.",
        "known_exploits": [],
    },
    "SWC-126": {
        "name": "Insufficient Gas Griefing",
        "description": "An attacker can manipulate gas forwarded to a sub-call, causing it to fail "
                       "while the outer call succeeds, leaving state inconsistent.",
        "category": "denial_of_service",
        "domains": ["blockchain", "appsec"],
        "severity": "medium",
        "example_pattern": "relayer.call{gas: userSpecifiedGas}(data);  // user controls gas",
        "mitigation": "Validate gas is sufficient. Use EIP-2771 meta-transactions correctly.",
        "offensive_notes": "Supply just enough gas to pass outer check but fail inner call.",
        "defensive_notes": "Gas stipend calculations must be conservative. Use try/catch.",
        "auditor_notes": "Find calls with user-specified gas. Check relayer patterns.",
        "known_exploits": [],
    },
    "SWC-127": {
        "name": "Arbitrary Jump with Function Type Variable",
        "description": "Function type variables can be set to arbitrary addresses, "
                       "allowing attacker to redirect execution.",
        "category": "access_control",
        "domains": ["appsec", "blockchain"],
        "severity": "critical",
        "example_pattern": "function execute(bytes4 sig, address target) external { target.call(sig); }",
        "mitigation": "Use function selectors with strict whitelisting. Avoid dynamic dispatch to user input.",
        "offensive_notes": "Set function pointer to selfdestruct or other privileged operation.",
        "defensive_notes": "Restrict function type variables. Audit all dynamic calls.",
        "auditor_notes": "Find function type variables settable from user input.",
        "known_exploits": [],
    },
    "SWC-128": {
        "name": "DoS With Block Gas Limit",
        "description": "Operations that scale with user-controlled input can exceed block gas limit, "
                       "permanently locking contract functionality.",
        "category": "denial_of_service",
        "domains": ["appsec", "blockchain"],
        "severity": "high",
        "example_pattern": "for (uint i = 0; i < users.length; i++) { distribute(); }  // unbounded loop",
        "mitigation": "Limit loop sizes. Pagination for large operations. Pull-over-push pattern.",
        "offensive_notes": "Register many addresses to make distribution loop exceed gas limit.",
        "defensive_notes": "Set maximum array sizes. Process in batches with checkpointing.",
        "auditor_notes": "Find unbounded loops. Check if array size is user-influenced.",
        "known_exploits": ["Governmental Ponzi — gas limit trapped ETH permanently"],
    },
    "SWC-129": {
        "name": "Typographical Error",
        "description": "Single character typos in operators (|= vs ||=, &= vs &&=) cause "
                       "unintended bitwise operations instead of logical ones.",
        "category": "logic_error",
        "domains": ["appsec"],
        "severity": "low",
        "example_pattern": "if (a |= b)  // bitwise OR assign, not logical OR",
        "mitigation": "Code review, testing. Use linters that catch operator confusion.",
        "offensive_notes": "Condition may always be true — bypass security checks.",
        "defensive_notes": "Add explicit test cases for boundary conditions in conditionals.",
        "auditor_notes": "Manual review for |= and &= in conditional contexts.",
        "known_exploits": [],
    },
    "SWC-130": {
        "name": "Right-To-Left-Override Control Character",
        "description": "Unicode RTL override characters (U+202E) can disguise malicious code "
                       "by making it appear as a comment.",
        "category": "logic_error",
        "domains": ["appsec"],
        "severity": "medium",
        "example_pattern": "/* comment \\u202e malicious_code */  // RTL makes code look like comment",
        "mitigation": "Use linters that detect non-ASCII characters in source. Audit imported code.",
        "offensive_notes": "Hide malicious logic in code that appears visually benign.",
        "defensive_notes": "Ban RTL Unicode in source files. Use CI check for Unicode anomalies.",
        "auditor_notes": "Run Unicode scan on source files. Important for imported/third-party code.",
        "known_exploits": [],
    },
    "SWC-131": {
        "name": "Presence of Unused Variables",
        "description": "Unused state variables or return values indicate poor code quality "
                       "and potential logic errors.",
        "category": "logic_error",
        "domains": ["appsec"],
        "severity": "low",
        "example_pattern": "uint256 public unused;  // declared but never set",
        "mitigation": "Remove unused variables. Run Solhint/Slither no-unused-vars rule.",
        "offensive_notes": "Unused vars rarely exploitable but indicate incomplete implementation.",
        "defensive_notes": "Clean up unused variables. They add confusion and deployment gas cost.",
        "auditor_notes": "Flag unused variables. Low severity but deducts from code quality.",
        "known_exploits": [],
    },
    "SWC-132": {
        "name": "Unexpected Ether Balance",
        "description": "Contract logic assumes its Ether balance equals the tracked internal accounting, "
                       "but Ether can be force-sent via selfdestruct or coinbase reward.",
        "category": "logic_error",
        "domains": ["blockchain", "appsec"],
        "severity": "medium",
        "example_pattern": "require(address(this).balance == expectedBalance);  // can be broken by force-send",
        "mitigation": "Never use address(this).balance as a security check. Use internal accounting.",
        "offensive_notes": "Force-send tiny ETH via selfdestruct → break invariant → lock contract.",
        "defensive_notes": "Use internal balance tracking, not address(this).balance for logic.",
        "auditor_notes": "Find require(address(this).balance == X). Flag as logic vulnerability.",
        "known_exploits": [],
    },
    "SWC-133": {
        "name": "Hash Collisions with Multiple Variable Length Arguments",
        "description": "abi.encodePacked with multiple dynamic types can produce hash collisions, "
                       "allowing signature forgery.",
        "category": "cryptography",
        "domains": ["cryptography", "appsec"],
        "severity": "high",
        "example_pattern": 'keccak256(abi.encodePacked(a, b))  // "aa"+"b" == "a"+"ab" if both strings',
        "mitigation": "Use abi.encode instead of abi.encodePacked for multiple dynamic types. "
                      "Or separate with fixed-length type (like address) in between.",
        "offensive_notes": "Find hash-verified signatures using encodePacked → construct collision.",
        "defensive_notes": "Use abi.encode. If encodePacked needed, include fixed-size separator.",
        "auditor_notes": "Find keccak256(abi.encodePacked(...)) with multiple dynamic args.",
        "known_exploits": [],
    },
    "SWC-134": {
        "name": "Message call with hardcoded gas amount",
        "description": "Hardcoded gas stipends (.transfer() or .send() use 2300 gas) may fail "
                       "when recipient is a contract with expensive fallback.",
        "category": "denial_of_service",
        "domains": ["appsec", "blockchain"],
        "severity": "medium",
        "example_pattern": "payable(addr).transfer(amount);  // 2300 gas may not be enough for contract receiver",
        "mitigation": "Use call{value: amount}('') and handle return value. Check effects first.",
        "offensive_notes": "Create contract with expensive fallback to DoS payment loop.",
        "defensive_notes": "Migrate from transfer() to call{value}. Use ReentrancyGuard to compensate.",
        "auditor_notes": "Flag .transfer() and .send() usage. Recommend migration to .call{value}.",
        "known_exploits": [],
    },
    "SWC-135": {
        "name": "Code With No Effects",
        "description": "Expressions with no side effects (like standalone function calls whose result "
                       "is discarded) indicate logic errors.",
        "category": "logic_error",
        "domains": ["appsec"],
        "severity": "low",
        "example_pattern": "address.call(data);  // return value not captured — same as no-effect",
        "mitigation": "Capture and check return values of all calls.",
        "offensive_notes": "Call result is ignored — function may revert silently, bypassing intent.",
        "defensive_notes": "Compiler warning for ignored return values. Enable warnings as errors.",
        "auditor_notes": "Find .call() without capturing return value.",
        "known_exploits": [],
    },
    "SWC-136": {
        "name": "Unencrypted Private Data On-Chain",
        "description": "Marking state variables private does not prevent reading from blockchain storage. "
                       "Sensitive data is readable by anyone.",
        "category": "logic_error",
        "domains": ["blockchain", "appsec"],
        "severity": "medium",
        "example_pattern": "bytes32 private secretKey;  // readable via eth_getStorageAt",
        "mitigation": "Never store sensitive plaintext data on-chain. Use off-chain encryption with "
                      "on-chain commitment or ZK proofs.",
        "offensive_notes": "Read storage slot directly via eth_getStorageAt — no permission needed.",
        "defensive_notes": "Educate team: on-chain data is public. Use ZK or commit-reveal.",
        "auditor_notes": "Flag 'private' vars that appear to hold secrets (keys, passwords, seeds).",
        "known_exploits": [],
    },
}


# ─── DeFi-specific attack patterns (not in SWC) ────────────────────────────────

DEFI_ATTACK_PATTERNS: Dict[str, Dict[str, Any]] = {
    "FLASH_LOAN_PRICE_MANIPULATION": {
        "name": "Flash Loan Price Oracle Manipulation",
        "description": "Attacker borrows large amount via flash loan to manipulate a spot-price DEX oracle, "
                       "then exploits mispriced collateral or arbitrage.",
        "category": "front_running",
        "domains": ["defi", "blockchain"],
        "severity": "critical",
        "prerequisite": "Contract uses spot price from AMM (Uniswap v2) as price oracle.",
        "mitigation": "Use TWAP oracle (Uniswap v3) or Chainlink. Add price deviation circuit breaker.",
        "offensive_notes": "Step 1: flash borrow large amount. Step 2: dump on DEX to crash price. "
                           "Step 3: exploit mispriced collateral. Step 4: repay flash loan.",
        "defensive_notes": "Replace spot oracle with Chainlink or TWAP. Add max price deviation check.",
        "auditor_notes": "If uses_oracle=True, check oracle source. Spot price from DEX = critical.",
        "known_exploits": ["PancakeBunny 2021 — $45M", "Mango Markets 2022 — $117M",
                           "CREAM Finance 2021 — $130M"],
    },
    "GOVERNANCE_FLASH_LOAN": {
        "name": "Governance Attack via Flash Loan",
        "description": "Attacker borrows governance tokens, passes malicious proposal, executes, "
                       "then returns tokens — all in one transaction.",
        "category": "governance",
        "domains": ["governance", "defi"],
        "severity": "critical",
        "prerequisite": "Governance counts token balance at voting time (snapshot at proposal creation).",
        "mitigation": "Voting delay after token acquisition. Time-lock on proposal execution. "
                      "Quorum from historical snapshots (ERC20Votes).",
        "offensive_notes": "Flash borrow > quorum of governance tokens → create proposal + vote + execute "
                           "in single transaction → return tokens.",
        "defensive_notes": "Use ERC20Votes (snapshot-based voting power). Require 48h delay between "
                           "proposal creation and voting. Time-lock on execution.",
        "auditor_notes": "If Governance contract type, check voting power calculation. "
                         "Flash loan attack possible if uses current balance.",
        "known_exploits": ["Beanstalk 2022 — $182M", "Build Finance 2022 — $470K"],
    },
    "SANDWICH_ATTACK": {
        "name": "Sandwich Attack (MEV Front/Back-run)",
        "description": "MEV bot sees victim AMM swap in mempool, front-runs to move price adversely, "
                       "lets victim execute at worse price, back-runs to profit.",
        "category": "front_running",
        "domains": ["defi"],
        "severity": "medium",
        "prerequisite": "AMM swap without minimum output / slippage protection.",
        "mitigation": "Set amountOutMin parameter. Use private mempool (Flashbots). Limit trade size.",
        "offensive_notes": "Monitor public mempool for large swaps with no slippage limit.",
        "defensive_notes": "Always set slippage tolerance ≤1% for large trades. Use deadline parameter.",
        "auditor_notes": "Check swapExactTokensForTokens and similar calls — verify amountOutMin is set.",
        "known_exploits": ["Pervasive MEV extraction — hundreds of millions/year across DeFi"],
    },
    "PRICE_ORACLE_STALENESS": {
        "name": "Stale Price Oracle Data",
        "description": "Chainlink or other oracles can become stale (no update) during network congestion. "
                       "Contract using stale price makes incorrect decisions.",
        "category": "logic_error",
        "domains": ["defi", "blockchain"],
        "severity": "high",
        "prerequisite": "Contract uses Chainlink oracle without checking updatedAt timestamp.",
        "mitigation": "Check updatedAt from latestRoundData(). Add MAX_STALENESS check (e.g., 1 hour).",
        "offensive_notes": "During congestion when oracle is stale, exploit mispriced collateral.",
        "defensive_notes": "require(block.timestamp - updatedAt <= MAX_STALENESS, 'Stale price')",
        "auditor_notes": "Find latestRoundData() calls — check if updatedAt is validated.",
        "known_exploits": ["Multiple lending protocol liquidation issues during high gas periods"],
    },
    "REENTRANCY_IN_DEFI": {
        "name": "Cross-Contract Reentrancy in DeFi Composability",
        "description": "Complex DeFi protocol interaction (vault + LP + lending) creates indirect "
                       "reentrancy paths across multiple contracts.",
        "category": "reentrancy",
        "domains": ["defi", "appsec"],
        "severity": "critical",
        "prerequisite": "Multiple contracts share state assumptions. Callback pattern enables re-entry.",
        "mitigation": "ReentrancyGuard across all fund-moving paths. Separate accounting from distribution.",
        "offensive_notes": "Use ERC777/ERC1155 callback hooks to re-enter during complex operation.",
        "defensive_notes": "Apply nonReentrant to all external-facing fund-moving functions.",
        "auditor_notes": "Trace all callback hooks (ERC777 tokensReceived, ERC721 onReceived). "
                         "Map cross-contract state dependencies.",
        "known_exploits": ["Euler Finance 2023 — $197M", "Fei Protocol 2022 — $80M"],
    },
    "ACCESS_CONTROL_MISCONFIGURATION": {
        "name": "DeFi Protocol Access Control Misconfiguration",
        "description": "Admin functions (pause, upgrade, drain) left accessible to deployer EOA "
                       "without timelock or multi-sig, creating centralization risk.",
        "category": "governance",
        "domains": ["governance", "appsec"],
        "severity": "high",
        "prerequisite": "Admin/owner is single EOA without timelock.",
        "mitigation": "Transfer ownership to multi-sig (Gnosis Safe) + timelock after deployment.",
        "offensive_notes": "Compromise deployer private key → pause, upgrade, drain entire protocol.",
        "defensive_notes": "Use OpenZeppelin TimelockController. Require 48h+ timelock for critical ops.",
        "auditor_notes": "Check ownership — if single EOA without timelock, flag as high severity.",
        "known_exploits": ["Poly Network 2021 — $611M", "Ronin Bridge 2022 — $625M"],
    },
}


# ─── Domain → SWC mapping ──────────────────────────────────────────────────────

SWC_BY_DOMAIN: Dict[str, List[str]] = {
    "appsec": [
        "SWC-104", "SWC-105", "SWC-106", "SWC-107",
        "SWC-113", "SWC-115", "SWC-128", "SWC-134",
    ],
    "blockchain": [
        "SWC-102", "SWC-103", "SWC-106", "SWC-107", "SWC-109", "SWC-112",
        "SWC-116", "SWC-120", "SWC-124", "SWC-126", "SWC-128", "SWC-132", "SWC-134",
    ],
    "cryptography": [
        "SWC-101", "SWC-120", "SWC-121", "SWC-122", "SWC-133",
    ],
    "defi": [
        "SWC-107", "SWC-113", "SWC-114", "SWC-128",
        # DeFi patterns:
        "FLASH_LOAN_PRICE_MANIPULATION", "SANDWICH_ATTACK",
        "PRICE_ORACLE_STALENESS", "REENTRANCY_IN_DEFI",
    ],
    "governance": [
        "SWC-105", "SWC-106", "SWC-112",
        # DeFi patterns:
        "GOVERNANCE_FLASH_LOAN", "ACCESS_CONTROL_MISCONFIGURATION",
    ],
}

# Attacker profile → SWC focus
SWC_BY_ATTACKER: Dict[str, List[str]] = {
    "reentrancy_bot": ["SWC-107", "REENTRANCY_IN_DEFI", "SWC-104", "SWC-134"],
    "flash_loan":     ["FLASH_LOAN_PRICE_MANIPULATION", "GOVERNANCE_FLASH_LOAN", "PRICE_ORACLE_STALENESS", "SWC-107"],
    "governance_attack": ["GOVERNANCE_FLASH_LOAN", "ACCESS_CONTROL_MISCONFIGURATION", "SWC-112", "SWC-115"],
    "mev_bot":        ["SANDWICH_ATTACK", "SWC-114", "SWC-116"],
    "supply_chain":   ["SWC-112", "SWC-124", "SWC-125", "SWC-130", "SWC-103"],
}


# ─── SWCRegistry class ─────────────────────────────────────────────────────────

class SWCRegistry:
    """
    Smart Contract Weakness Classification Registry.
    Thay thế MitreReference trong Hướng B.
    """

    def get_swc_context_for_agent(self, domain: str, persona: str) -> str:
        """
        Inject SWC context vào agent dựa trên domain + persona.
        Offensive → focus exploit path + known exploits
        Defensive → focus mitigation + detection
        Auditor   → focus compliance + code quality
        """
        persona_key = self._normalize_persona(persona)
        relevant_ids = SWC_BY_DOMAIN.get(domain, list(SWC_REGISTRY.keys())[:5])

        lines = [f"=== SWC Reference for {domain.upper()} domain ({persona_key} perspective) ===\n"]

        for swc_id in relevant_ids:
            entry = self._get_entry(swc_id)
            if not entry:
                continue

            lines.append(f"[{swc_id}] {entry['name']} (Severity: {entry.get('severity', 'unknown')})")
            lines.append(f"  Description: {entry['description']}")

            if persona_key == "offensive":
                lines.append(f"  EXPLOIT PATH: {entry.get('offensive_notes', 'N/A')}")
                exploits = entry.get("known_exploits", [])
                if exploits:
                    lines.append(f"  KNOWN ATTACKS: {'; '.join(exploits)}")
            elif persona_key == "defensive":
                lines.append(f"  MITIGATION: {entry.get('mitigation', 'N/A')}")
                lines.append(f"  DETECTION: {entry.get('defensive_notes', 'N/A')}")
            else:  # auditor
                lines.append(f"  AUDIT CHECK: {entry.get('auditor_notes', 'N/A')}")
                lines.append(f"  MITIGATION: {entry.get('mitigation', 'N/A')}")

            lines.append("")

        return "\n".join(lines)

    def get_swc_context_for_attacker(self, profile: str) -> str:
        """
        Inject SWC context cho attacker profile agents (Phase C).
        Focus on exploit paths and known real-world attacks.
        """
        relevant_ids = SWC_BY_ATTACKER.get(profile, ["SWC-107", "SWC-105"])

        lines = [f"=== Attack Context for {profile.upper()} attacker profile ===\n"]

        for swc_id in relevant_ids:
            entry = self._get_entry(swc_id)
            if not entry:
                continue

            lines.append(f"[{swc_id}] {entry['name']}")
            lines.append(f"  Description: {entry['description']}")
            lines.append(f"  EXPLOIT: {entry.get('offensive_notes', 'N/A')}")
            exploits = entry.get("known_exploits", [])
            if exploits:
                lines.append(f"  REAL ATTACKS: {'; '.join(exploits)}")

            # DeFi patterns have extra prereq field
            if "prerequisite" in entry:
                lines.append(f"  PREREQUISITE: {entry['prerequisite']}")

            lines.append("")

        return "\n".join(lines)

    def get_swc_for_domain(self, domain: str) -> List[Dict[str, Any]]:
        """Trả về list SWC entries relevant cho domain này."""
        ids = SWC_BY_DOMAIN.get(domain, [])
        return [
            {"id": sid, **self._get_entry(sid)}
            for sid in ids
            if self._get_entry(sid)
        ]

    def get_swc_by_id(self, swc_id: str) -> Optional[Dict[str, Any]]:
        """Tra cứu SWC entry theo ID (hoặc DeFi pattern key)."""
        return self._get_entry(swc_id)

    def get_defi_patterns_for_contract(self, contract_entity: "ContractEntity") -> List[Dict[str, Any]]:
        """
        Với ContractEntity cụ thể, trả về DeFi attack patterns relevant.
        Dựa trên structural flags trong entity.
        """
        results = []

        if contract_entity.uses_oracle:
            p = DEFI_ATTACK_PATTERNS.get("FLASH_LOAN_PRICE_MANIPULATION")
            if p:
                results.append({"id": "FLASH_LOAN_PRICE_MANIPULATION", **p})
            p = DEFI_ATTACK_PATTERNS.get("PRICE_ORACLE_STALENESS")
            if p:
                results.append({"id": "PRICE_ORACLE_STALENESS", **p})

        if contract_entity.contract_type in ("Governance", "DeFi_AMM", "DeFi_Lending"):
            p = DEFI_ATTACK_PATTERNS.get("GOVERNANCE_FLASH_LOAN")
            if p:
                results.append({"id": "GOVERNANCE_FLASH_LOAN", **p})

        if contract_entity.contract_type in ("DeFi_AMM",):
            p = DEFI_ATTACK_PATTERNS.get("SANDWICH_ATTACK")
            if p:
                results.append({"id": "SANDWICH_ATTACK", **p})

        if contract_entity.uses_flash_loan:
            p = DEFI_ATTACK_PATTERNS.get("REENTRANCY_IN_DEFI")
            if p:
                results.append({"id": "REENTRANCY_IN_DEFI", **p})

        # Access control check for governance risk
        if not contract_entity.has_access_control and contract_entity.contract_type in ("Vault", "DeFi_Lending"):
            p = DEFI_ATTACK_PATTERNS.get("ACCESS_CONTROL_MISCONFIGURATION")
            if p:
                results.append({"id": "ACCESS_CONTROL_MISCONFIGURATION", **p})

        return results

    def get_all_swc_ids(self) -> List[str]:
        """Trả về tất cả SWC IDs (bao gồm DeFi patterns)."""
        return list(SWC_REGISTRY.keys()) + list(DEFI_ATTACK_PATTERNS.keys())

    def get_severity_anchor_keywords(self) -> Dict[str, List[str]]:
        """
        Keywords để semantic anchor clustering trong ConsensusEngine.
        Thay thế MITRE_ANCHOR_KEYWORDS.
        """
        return {
            "reentrancy":     ["reentrancy", "re-entrancy", "reentrant", "SWC-107", "CEI"],
            "overflow":       ["overflow", "underflow", "arithmetic", "SafeMath", "SWC-101"],
            "access_control": ["access control", "onlyOwner", "authorization", "SWC-105", "SWC-115", "privilege"],
            "oracle":         ["oracle", "price manipulation", "TWAP", "Chainlink", "flash loan price"],
            "flash_loan":     ["flash loan", "flashloan", "FLASH_LOAN", "flash attack"],
            "governance":     ["governance", "voting", "proposal", "timelock", "GOVERNANCE_FLASH"],
            "randomness":     ["randomness", "PRNG", "entropy", "VRF", "SWC-120"],
            "selfdestruct":   ["selfdestruct", "suicide", "SWC-106"],
            "delegatecall":   ["delegatecall", "delegate call", "SWC-112", "proxy"],
            "signature":      ["signature", "ecrecover", "replay", "SWC-121", "SWC-122"],
        }

    # ─── Private helpers ──────────────────────────────────────────────────────

    def _get_entry(self, swc_id: str) -> Optional[Dict[str, Any]]:
        """Lookup in SWC_REGISTRY then DEFI_ATTACK_PATTERNS."""
        return SWC_REGISTRY.get(swc_id) or DEFI_ATTACK_PATTERNS.get(swc_id)

    def _normalize_persona(self, persona: str) -> str:
        """Map persona variants to canonical: offensive | defensive | auditor."""
        persona_lower = persona.lower()
        if any(k in persona_lower for k in ("offensive", "attacker", "red", "exploit", "penetr")):
            return "offensive"
        if any(k in persona_lower for k in ("defensive", "defender", "blue", "protect")):
            return "defensive"
        return "auditor"
