"""
Dry-run: test grouping + agent assignment trên contest 35 (toàn bộ contracts).
Không call LLM. Output:
  - Mỗi function → domain + agent
  - Mỗi group → danh sách functions + line count
  - Cảnh báo nếu vượt size limit
  - GT functions (H-01/03/05/16/17) có được assign đúng không
"""
import sys, os, re, glob
from collections import defaultdict

# ─── Config ───────────────────────────────────────────────────────────────────

CONTRACTS_DIR = '/home/thangdd/repos/web3bugs/contracts/35/trident/contracts'

# Bỏ qua: interfaces, test, flat, mocks, workInProgress
SKIP_DIRS = {'interfaces', 'test', 'workInProgress', 'flat', 'mocks'}

GT_FUNCTIONS = {
    'burn':                    'H-01',
    '_getAmountsForLiquidity': 'H-05',
    'reclaimIncentive':        'H-03',
    'claimReward':             'H-16',
    'rangeFeeGrowth':          'H-17',
}

GROUP_SIZE_LIMITS = {
    'clmm_semantic':  800,
    'math_cast':      700,
    'access_reward':  600,
    'economic':       700,
    'state_ordering': 700,
    'general':        600,
}

DOMAIN_AGENT_MAP = {
    'clmm_semantic':  ['clmm_specialist'],
    'math_cast':      ['evm_hardener'],
    'access_reward':  ['access_escalator'],
    'economic':       ['defi_attacker'],
    'state_ordering': ['state_machine_analyst'],
    'general':        ['invariant_breaker'],
}

# ─── Domain rules (specific trước, general sau) ───────────────────────────────

# Rules áp dụng trên fn_name riêng (word boundary — không bị nhiễu bởi natspec)
# Specific nhất trước, general sau
FN_NAME_RULES = [
    # clmm_semantic
    (r'\btick\b|range.?fee|fee.?growth|nearest.?tick|sqrt.?ratio|'
     r'seconds.?per|range.?seconds|get.?price.?and',          'clmm_semantic'),
    # math_cast — \b word boundary tránh nhầm burnSingle/mintFee
    (r'\bburn\b|\bmint\b|\bswap\b|flash.?swap|'
     r'get.?amount|amount.?for|get.?amounts|'
     r'_update.?position|_update.?fees|_update.?seconds|'
     r'_get.?amounts|_compute.?liquidity|get.?reserves|'
     r'add.?liquidity|remove.?liquidity|liquidity.?delta',     'math_cast'),
    # access_reward
    (r'\bclaim\b|reward|reclaim|subscribe|\bharvestb|'
     r'distribute|add.?incentive|remove.?incentive|get.?reward|get.?incentive|'
     r'stake\b|unstake',                                       'access_reward'),
    # economic
    (r'flash(?!swap)|oracle|twap|get.?price|update.?price|arbitrage', 'economic'),
    # state_ordering
    (r'initialize|callback|settle|\bsync\b|deploy.?pool|'
     r'create.?pool|create.?position',                         'state_ordering'),
]

def match_domain(fn_name: str, natspec: str = '') -> str:
    """Match domain: fn_name first (word-boundary), then fallback to natspec."""
    name_lower = fn_name.lower()
    for pattern, domain in FN_NAME_RULES:
        if re.search(pattern, name_lower, re.IGNORECASE):
            return domain
    # Fallback: try natspec
    if natspec:
        natspec_lower = natspec.lower()
        for pattern, domain in FN_NAME_RULES:
            if re.search(pattern, natspec_lower, re.IGNORECASE):
                return domain
    return 'general'

# ─── Function extractor ───────────────────────────────────────────────────────

def extract_fn_signatures(source: str) -> list[tuple[str, str, str]]:
    """
    Returns list of (fn_name, signature_line, natspec).
    Handles multi-line signatures: only requires opening paren on same line.
    """
    lines = source.split('\n')
    results = []
    natspec_buf = []

    for line in lines:
        stripped = line.strip()

        # Accumulate NatSpec / comments
        if (stripped.startswith('///') or stripped.startswith('* ')
                or stripped.startswith('/**') or stripped.startswith('/*')
                or stripped.startswith('* @')):
            natspec_buf.append(stripped)
            continue

        # Match function declaration — only need opening paren (handles multi-line params)
        m = re.match(r'^(?:function|constructor)\s+(\w+)\s*\(', stripped)
        if m:
            fn_name = m.group(1)
            natspec = ' '.join(natspec_buf[-5:])
            results.append((fn_name, stripped[:120], natspec))
            natspec_buf = []
            continue

        # Reset NatSpec on blank or non-comment lines
        if not stripped or (not stripped.startswith('//') and not stripped.startswith('*')):
            natspec_buf = []

    return results

def count_fn_lines(source: str, fn_name: str) -> int:
    """Rough line count for a named function body."""
    lines = source.split('\n')
    in_fn, depth, count = False, 0, 0
    for line in lines:
        m = re.match(r'^\s*function\s+' + re.escape(fn_name) + r'\s*[\(\{]', line)
        if m:
            in_fn = True
        if in_fn:
            count += 1
            depth += line.count('{') - line.count('}')
            if depth <= 0 and count > 1:
                break
    return count

# ─── Load contracts ───────────────────────────────────────────────────────────

def should_skip(path: str) -> bool:
    parts = path.split(os.sep)
    return any(d in SKIP_DIRS for d in parts)

contracts = []
for sol_path in sorted(glob.glob(f'{CONTRACTS_DIR}/**/*.sol', recursive=True)):
    if should_skip(sol_path):
        continue
    contract_name = os.path.splitext(os.path.basename(sol_path))[0]
    source = open(sol_path).read()
    # Skip pure interface files (only function signatures, no bodies)
    if source.count('{') < 3:
        continue
    contracts.append((contract_name, source, sol_path))

print(f"Loaded {len(contracts)} contracts (after filtering)\n")

# ─── Group functions ──────────────────────────────────────────────────────────

# domain → list of (contract, fn_name, sig, natspec, approx_lines)
groups = defaultdict(list)
all_assignments = []   # for GT check

for contract_name, source, path in contracts:
    fns = extract_fn_signatures(source)
    for fn_name, sig, natspec in fns:
        domain = match_domain(fn_name, natspec)
        approx_lines = count_fn_lines(source, fn_name)
        groups[domain].append((contract_name, fn_name, sig, natspec, approx_lines))
        all_assignments.append({
            'contract': contract_name,
            'fn': fn_name,
            'domain': domain,
            'agent': DOMAIN_AGENT_MAP[domain][0],
            'lines': approx_lines,
            'gt': GT_FUNCTIONS.get(fn_name, ''),
        })

# ─── Print per-group summary ──────────────────────────────────────────────────

COLORS = {
    'clmm_semantic':  '\033[94m',   # blue
    'math_cast':      '\033[92m',   # green
    'access_reward':  '\033[93m',   # yellow
    'economic':       '\033[95m',   # magenta
    'state_ordering': '\033[96m',   # cyan
    'general':        '\033[90m',   # gray
}
RESET = '\033[0m'
BOLD  = '\033[1m'
RED   = '\033[91m'
GREEN = '\033[92m'

print('=' * 80)
print(f"{BOLD}GROUP ASSIGNMENTS — contest 35{RESET}")
print('=' * 80)

domain_order = ['clmm_semantic', 'math_cast', 'access_reward', 'economic', 'state_ordering', 'general']

total_fn = 0
for domain in domain_order:
    entries = groups[domain]
    if not entries:
        continue

    agents = DOMAIN_AGENT_MAP[domain]
    total_lines = sum(e[4] for e in entries)
    limit = GROUP_SIZE_LIMITS[domain]
    over = total_lines > limit
    color = COLORS[domain]

    print(f"\n{color}{BOLD}[{domain}]{RESET}  agent={agents}  "
          f"fns={len(entries)}  lines≈{total_lines}  "
          f"{'⚠️  OVER LIMIT (' + str(limit) + ')' if over else '✓'}")
    print(f"  {'Contract':<40} {'Function':<35} {'Lines':>5}  {'GT?':>5}")
    print(f"  {'─'*40} {'─'*35} {'─'*5}  {'─'*5}")

    for contract, fn_name, sig, natspec, lines in sorted(entries, key=lambda x: x[0]):
        gt_tag = GT_FUNCTIONS.get(fn_name, '')
        gt_str = f"{GREEN}{BOLD}{gt_tag}{RESET}" if gt_tag else ''
        marker = ' ←' if gt_tag else ''
        print(f"  {contract:<40} {fn_name:<35} {lines:>5}{marker}  {gt_str}")
    total_fn += len(entries)

# ─── GT function check ────────────────────────────────────────────────────────

print(f"\n{'=' * 80}")
print(f"{BOLD}GT FUNCTION CHECK{RESET}")
print('=' * 80)

gt_check = {fn: [] for fn in GT_FUNCTIONS}
for a in all_assignments:
    if a['fn'] in GT_FUNCTIONS:
        gt_check[a['fn']].append(a)

for fn_name, h_id in GT_FUNCTIONS.items():
    matches = gt_check[fn_name]
    if not matches:
        print(f"  {RED}✗ {h_id} ({fn_name}): NOT FOUND in any contract{RESET}")
        continue
    for m in matches:
        correct = m['domain'] in ('clmm_semantic' if fn_name in ('rangeFeeGrowth',) else
                                   'math_cast' if fn_name in ('burn', '_getAmountsForLiquidity') else
                                   'access_reward')
        sym = f"{GREEN}✓{RESET}" if correct else f"  {RED}✗ WRONG DOMAIN{RESET}"
        print(f"  {sym} {h_id} ({fn_name}) in {m['contract']}")
        print(f"      domain={m['domain']}  agent={m['agent']}  lines≈{m['lines']}")

# ─── Size warning & split recommendation ─────────────────────────────────────

print(f"\n{'=' * 80}")
print(f"{BOLD}SIZE ANALYSIS{RESET}")
print('=' * 80)

for domain in domain_order:
    entries = groups[domain]
    if not entries:
        continue
    total_lines = sum(e[4] for e in entries)
    limit = GROUP_SIZE_LIMITS[domain]
    if total_lines > limit:
        # Count per-contract
        per_contract = defaultdict(list)
        for e in entries:
            per_contract[e[0]].append(e)
        print(f"\n  {RED}⚠ [{domain}] {total_lines} lines > limit {limit}{RESET}")
        print(f"     Recommendation: split per-contract:")
        for cname, centry in sorted(per_contract.items()):
            clines = sum(e[4] for e in centry)
            print(f"       {cname}: {len(centry)} fns, ~{clines} lines")
    else:
        print(f"  ✓ [{domain}] {total_lines} lines ≤ {limit}")

# ─── Overall stats ────────────────────────────────────────────────────────────

print(f"\n{'=' * 80}")
print(f"{BOLD}OVERALL STATS{RESET}")
print('=' * 80)
print(f"  Total contracts analyzed : {len(contracts)}")
print(f"  Total functions grouped  : {total_fn}")
print(f"  Total LLM calls (R1 T1+T2): {sum(len(DOMAIN_AGENT_MAP[d]) for d in groups if d in DOMAIN_AGENT_MAP) * 2}")
print(f"  vs current pipeline      : 44 calls")
print()
for domain in domain_order:
    entries = groups[domain]
    if not entries:
        continue
    agents = DOMAIN_AGENT_MAP[domain]
    print(f"  {domain:<18} {len(entries):>3} fns  {len(agents)} agent(s) × 2 turns")
