# [H-02] Partial signature replay/frontrunning attack on session calls

**Impact:** HIGH  
**Protocol:** Sequence  
**Firm:** Code4rena  
**Quality Score:** 5  
**General Score:** 4.333333333333333  
**Finders:** 1  
**Contest Prize:** $73000  
**Source:** https://code4rena.com/reports/2025-10-sequence  

## Summary

This bug report discusses a vulnerability in the code that handles session calls in the `Calls.sol` and `SessionSig.sol` files. When a session call with `BEHAVIOR_REVERT_ON_ERROR` fails, the entire execution reverts but the signature remains valid. This allows attackers to forge a valid partial signature and execute calls that were not intended to run independently. Additionally, if an attacker has access to the mempool, they can frontrun a multi-call session and execute only a subset of calls, potentially causing financial loss, state corruption, or bypassing security measures. The recommended mitigation steps involve binding session call signatures to the complete payload hash to prevent partial signature replay. A proof of concept is also provided in the `POC.t.sol` file.

## Full Content

<https://github.com/code-423n4/2025-10-sequence/blob/b0e5fb15bf6735ec9aaba02f5eca28a7882d815d/src/modules/Calls.sol# L36-L48>

<https://github.com/code-423n4/2025-10-sequence/blob/b0e5fb15bf6735ec9aaba02f5eca28a7882d815d/src/modules/Calls.sol# L61-L123>

<https://github.com/code-423n4/2025-10-sequence/blob/b0e5fb15bf6735ec9aaba02f5eca28a7882d815d/src/extensions/sessions/SessionSig.sol# L136-L176>

When a session call with `BEHAVIOR_REVERT_ON_ERROR` behavior fails, the entire execution reverts but the signature remains valid, since nonce is not yet consumed. Attackers can forge a valid partial signature from failed multi-call session, executing partial calls that were never intended to run independently.

Moreover, if an attacker has access to mempool, they can frontrun a multi-call session to execute only a subset of calls to either grief the legitimate call, or inflict financial damage to the wallet owners.

### Finding description and impact

The `Calls` contract consumes nonces before signature validation and execution...

### Recommended mitigation steps

Bind session call signatures to the complete payload hash to prevent partial signature replay.
