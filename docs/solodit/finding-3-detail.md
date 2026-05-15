# [H-01] Chained signature with checkpoint usage disabled can bypass all checkpointer validation

**Impact:** HIGH  
**Protocol:** Sequence  
**Firm:** Code4rena  
**Quality Score:** 5  
**General Score:** 5  
**Finders:** 1  
**Contest Prize:** $73000  
**Source:** https://code4rena.com/reports/2025-10-sequence  

## Summary

This bug report discusses a potential vulnerability in a code that is used for signing transactions in a wallet. The bug occurs when a specific scenario is met, where the wallet is behind a checkpointer and a chained signature is used. This leads to certain variables being left unset, which can allow an evicted signer to maliciously sign a payload and perform unauthorized operations on the wallet. The report recommends a mitigation step to prevent this bug from occurring and provides a proof of concept test case to demonstrate the issue.

## Full Content

<https://github.com/code-423n4/2025-10-sequence/blob/b0e5fb15bf6735ec9aaba02f5eca28a7882d815d/src/modules/auth/BaseSig.sol# L88>

### Finding description and impact

Consider a scenario where (1) the wallet is behind the checkpointer and (2) a chained signature is used; however, bit 6 (`0x40` - the checkpointer usage flag) is zero. As a result, when `BaseSig.recover` is called the below if-block on `BaseSig.sol:88-106` will be skipped.

We can see that this will leave the following variables unset (zero-valued):

* `_checkpointer`
* `snapshot.checkpoint`
* `snapshot.imageHash`

**Impact:** an evicted signer can maliciously sign a payload (valid with respect to the stale wallet configuration) and perform operations on the wallet.

### Recommended mitigation steps

Do not permit the checkpointer to be disabled in the signature (bit 6 left unset) if a chained signature is used. The signature recovery should revert in this case.
