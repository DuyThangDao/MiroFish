High Risk Findings (3) 
 [H-01] Order double-linked list is broken because order.prevOrderId is not persisted 
 Submitted by montecristo , also found by 0x1998 , 0xAsen , 0xdice91 , 0xlookman , 0xPhantom , axelot , ayden , BenRai , boredpukar , DDEENNY , dhank , Drynooo , Egbe , gh0xt , JuggerNaut63 , lodelux , Olugbenga , Ragnarok , Riceee , sedare64 , surenyanoks , taticuvostru , touristS , volodya , and VulnViper 
 
 clob/types/Book.sol #L275-L289 
 clob/types/Book.sol #L150-L154 
 
 order.prevOrderId is updated only in memory and not saved to storage, breaking the linked list. This causes order adding and removal issues, potentially leading to denial of service when the order book is full and the limit’s tailOrder becomes invalid. 
 Description 
 Orders are stored as a double-linked list in the book. 
 However, this linking is broken as order.prevOrderId is not actually stored in EVM storage: 
 File: contracts/clob/types/Book.sol 
 150 : function addOrderToBook ( Book storage self , Order memory order ) internal { 
 151 : Limit storage limit = _updateBookPostOrder ( self , order ); 
 152 : 
 153 :@> _updateLimitPostOrder ( self , limit , order ); 
 154 : } 
 As we can see in the above code, linked list is updated in the end. And order is passed as memory type: 
 File: contracts/clob/types/Book.sol 
 275 : function _updateLimitPostOrder ( Book storage self , Limit storage limit , Order memory order ) private { 
 276 : limit . numOrders ++; 
 277 : 
 278 : if ( limit . headOrder . isNull ()) { 
 279 : limit . headOrder = order . id ; 
 280 : limit . tailOrder = order . id ; 
 281 : } else { 
 282 : Order storage tailOrder = self . orders [ limit . tailOrder ]; 
 283 : tailOrder . nextOrderId = order . id ; 
 284 :@> order . prevOrderId = tailOrder . id ; 
 285 : limit . tailOrder = order . id ; 
 286 : } 
 287 : 
 288 : emit LimitOrderCreated ( BookEventNonce . inc (), order . id , order . price , order . amount , order . side ); 
 289 : } 
 In L284, order.prevOrderId is updated. However, it is not stored in EVM storage because order is passed as memory in L275. 
 This completely breaks linked list in future operations. For example, when removing orders: 
 File: contracts/clob/types/Book.sol 
 320 : OrderId prev = order . prevOrderId ; 
 321 : OrderId next = order . nextOrderId ; 
 322 : 
 323 : if (! prev . isNull ()) self . orders [ prev ]. nextOrderId = next ; 
 324 : else limit . headOrder = next ; 
 325 : 
 326 : if (! next . isNull ()) self . orders [ next ]. prevOrderId = prev ; 
 327 : else limit . tailOrder = prev ; 
 
 prev will be null in L320 because prevOrderId was not persisted 
 Thus, L323 will not be reached and L324 will always be reached. This means prev and next linkage will be broken 
 In L327, limit.tailOrder will always be set to null if removed entry was the tail 
 
 Impact 
 Order adding/removal will be affected. 
 Especially, when order book is full, CLOB can face DoS because limit tailOrder is set to empty order due to broken linked list. 
 This DoS is demonstrated by a POC. 
 View detailed Proof of Concept 
 
 [H-02] Dust orders can block order posting 
 Submitted by montecristo , also found by 0xAsen , gesha17 , gizzy , holtzzx , newspacexyz , and solhhj 
 clob/CLOB.sol #L807-L849 
 When matching incoming orders, maker orders can be reduced below the minimum limit without checks, resulting in dust positions remaining in the order book. These dust orders can block new incoming orders, as matching them may revert with a ZeroCostTrade error if the quote amount rounds down to zero. 
 Description 
 When matching an incoming order, maker order’s amount can be set below minLimitOrderAmountInBase , as there is no min amount check: 
 File: contracts/clob/CLOB.sol 
 833 :@> bool orderRemoved = matchData . baseDelta == matchedBase ; 
 834 : 
 835 : // Handle token accounting for maker. 
 836 : if ( takerOrder . side == Side . BUY ) { 
 837 : TransientMakerData . addQuoteToken ( makerOrder . owner , matchData . quoteDelta ); 
 838 : 
 839 : if (! orderRemoved ) ds . metadata (). baseTokenOpenInterest -= matchData . baseDelta ; 
 840 : } else { 
 841 : TransientMakerData . addBaseToken ( makerOrder . owner , matchData . baseDelta ); 
 842 : 
 843 : if (! orderRemoved ) ds . metadata (). quoteTokenOpenInterest -= matchData . quoteDelta ; 
 844 : } 
 845 : 
 846 : if ( orderRemoved ) ds . removeOrderFromBook ( makerOrder ); 
 847 :@> else makerOrder . amount -= matchData . baseDelta ; 
 
 In L833, order is removed only when matched amount is equal to maker order’s amount 
 In L847, maker order’s amount is decreased by matched amount. The result amount can be dust, as there is no min amount check done afterwards. 
 
 As such, maker order’s amount can be a dust amount (up to lotSizeInBase config). 
 This means there can be a dust position in the order book. 
 What happens if this dust order is matched to another incoming order? 
 File: contracts/clob/CLOB.sol 
 819 : matchData . baseDelta = ( matchedBase . min ( takerOrder . amount ) / lotSize ) * lotSize ; 
 820 : matchData . quoteDelta = ds . getQuoteTokenAmount ( matchedPrice , matchData . baseDelta ); 
 
 In L819, matchData.baseDelta can be as small as lotSize , since makeOrder.amount can be down to lotSize 
 In L820, matchData.quoteDelta can be zero due to rounddown: 
 
 File: contracts/clob/types/Book.sol 
 471 : function getQuoteTokenAmount ( Book storage self , uint256 price , uint256 baseAmount ) 
 472: internal 
 473: view 
 474: returns ( uint256 quoteAmount ) 
 475: { 
 476 : return baseAmount * price / self . config (). baseSize ; 
 477 : } 
 If matchData.quoteDelta is 0, the trade(or order posting) will revert with ZeroCostTrade error: 
 File: contracts/clob/CLOB.sol 
 439 : if ( totalQuoteSent == 0 || totalBaseReceived == 0 ) revert ZeroCostTrade (); 
 Impact 
 Dust positions can block incoming orders. An example is shown in the POC. 
 Recommended Mitigation Steps 
 Consider removing orders if the amount after matching is lower than minLimitOrderAmountInBase . 
 View detailed Proof of Concept 
 
 [H-03] DOS Attack via Order Amendment Bypassing maxLimitsPerTx Protection 
 Submitted by eightzerofour , also found by lonelybones 
 clob/CLOB.sol #L390 
 The CLOB (Central Limit Order Book) system implements DOS protection through the maxLimitsPerTx parameter, which limits the number of new limit orders a user can place within a single transaction. However, the amend() function allows users to bypass this critical protection mechanism by amending existing orders to different price levels without incrementing the transaction limit counter. This enables attackers to flood the order book with unlimited price level changes in a single transaction, effectively circumventing the protocol’s DOS protection. 
 Vulnerability Details 
 The vulnerability stems from the fact that the amend() function in CLOB.sol does not call incrementLimitsPlaced() when an order is amended to a new price or side, even though such amendments effectively create new order book entries at different price levels. 
 In CLOB.sol , the postLimitOrder function properly enforces DOS protection: 
 function postLimitOrder ( address account , PostLimitOrderArgs calldata args ) 
 external 
 onlySenderOrOperator ( account , OperatorRoles.CLOB_LIMIT) 
 returns ( PostLimitOrderResult memory ) 
 { 
 Book storage ds = _getStorage (); 
 
 ds . assertLimitPriceInBounds ( args . price ); 
 ds . assertLimitOrderAmountInBounds ( args . amountInBase ); 
 ds . assertLotSizeCompliant ( args . amountInBase ); 
 
 // Max limits per tx is enforced on the caller to allow for whitelisted operators 
 // to implement their own max limit logic. 
 ds . incrementLimitsPlaced ( address ( factory ), msg . sender ); 
 
 uint256 orderId ; 
 if ( args . clientOrderId == 0 ) { 
 orderId = ds . incrementOrderId (); 
 } else { 
 orderId = account . getOrderId ( args . clientOrderId ); 
 ds . assertUnusedOrderId ( orderId ); 
 } 
 
 Order memory newOrder = args . toOrder ( orderId , account ); 
 
 if ( newOrder . isExpired ()) revert OrderExpired (); 
 
 emit LimitOrderSubmitted ( CLOBEventNonce . inc (), account , orderId , args ); 
 
 if ( args . side == Side . BUY ) return _processLimitBidOrder ( ds , account , newOrder , args ); 
 else return _processLimitAskOrder ( ds , account , newOrder , args ); 
 } 
 However, the amend() function bypasses this protection entirely: 
 function amend ( address account , AmendArgs calldata args ) 
 external 
 override 
 onlyOperatorCallback 
 returns ( int256 quoteTokenDelta , int256 baseTokenDelta ) 
 { 
 Book storage ds = CLOBStorageLib . getStorage (); 
 
 // No call to incrementLimitsPlaced() here! 
 
 Order storage order = ds . orders [ args . orderId . toOrderId ()]; 
 order . assertExists (); 
 
 if ( order . owner != account ) revert Unauthorized (); 
 
 return _processAmend ( ds , order , args ); 
 } 
 When amending to a new price/side, the _executeAmendNewOrder function effectively creates a new order: 
 function _executeAmendNewOrder ( Book storage ds , Order storage order , AmendArgs calldata args ) 
 internal 
 returns ( int256 quoteTokenDelta , int256 baseTokenDelta ) 
 { 
 // Removes order from current position 
 ds . removeOrderFromBook ( order ); 
 
 // Creates new order with new parameters 
 Order memory newOrder = Order ({ 
 id: order . id , 
 prevOrderId: OrderId . wrap ( 0 ), 
 nextOrderId: OrderId . wrap ( 0 ), 
 owner: order . owner , 
 amount: args . amountInBase , 
 price: args . price , 
 side: args . side , 
 cancelTimestamp: args . cancelTimestamp 
 }); 
 
 // Places order at new position - effectively a new limit order 
 if ( args . side == Side . BUY ) { 
 return _executeBidLimitOrder ( ds , newOrder , args . limitOrderType ); 
 } else { 
 return _executeAskLimitOrder ( ds , newOrder , args . limitOrderType ); 
 } 
 } 
 Impact (Attack Vectors) 
 Order Book Flooding : Attackers can create unlimited order book activity in a single transaction by repeatedly amending orders to different price levels, completely bypassing the maxLimitsPerTx protection designed to prevent this exact scenario. 
 
 It can be executed by any user with minimal capital (just enough for 2 initial orders) 
 It can be automated and repeated across multiple transactions to maintain the attack 
 
 Recommended Mitigation Steps 
 A possible mitigation would be implemented by modifying the _processAmend function in CLOB.sol to enforce DOS protection when an order is amended to a different price or side. 
 Fix Applied: 
 function _processAmend ( Book storage ds , Order storage order , AmendArgs calldata args ) 
 internal 
 returns ( int256 quoteTokenDelta , int256 baseTokenDelta ) 
 { 
 Order memory preAmend = order ; 
 address maker = preAmend . owner ; 
 
 if ( args . cancelTimestamp . isExpired () || args . amountInBase < ds . settings (). minLimitOrderAmountInBase ) { 
 revert AmendInvalid (); 
 } 
 
 // Check lot size compliance after other validations 
 ds . assertLotSizeCompliant ( args . amountInBase ); 
 
 if ( order . side != args . side || order . price != args . price ) { 
 // change place in book - this effectively creates a new order position, 
 // so we need to enforce DOS protection by checking limits 
 ds . incrementLimitsPlaced ( address ( factory ), msg . sender ); 
 ( quoteTokenDelta , baseTokenDelta ) = _executeAmendNewOrder ( ds , order , args ); 
 } else { 
 // change amount - no new position created, no limit check needed 
 ( quoteTokenDelta , baseTokenDelta ) = _executeAmendAmount ( ds , order , args . amountInBase ); 
 
 if ( quoteTokenDelta + baseTokenDelta == 0 ) revert ZeroOrder (); 
 } 
 emit OrderAmended ( CLOBEventNonce . inc (), preAmend , args , quoteTokenDelta , baseTokenDelta ); 
 
 _settleAmend ( ds , maker , quoteTokenDelta , baseTokenDelta ); 
 } 
 When an order amendment changes the price or side ( order.side != args.side || order.price != args.price ), the function now calls ds.incrementLimitsPlaced(address(factory), msg.sender) before executing the amendment. Amount-only amendments (same price and side) do not trigger the limit check since they don’t create new order book positions. The fix ensures that both postLimitOrder and amend operations that create new order book positions are subject to the same DOS protection mechanism. 
 Verification: 
 The fix was validated by running the existing test, which now demonstrates that: 
 
 Normal DOS protection works: Cannot post more than maxLimitsPerTx orders 
 Cannot amend orders to new positions when limit is reached 
 The attack is prevented: The first amendment attempt fails with LimitsPlacedExceedsMax() error 
 
 View detailed Proof of Concept 
 
 Medium Risk Findings (4) 
 [M-01] Flawed Zero-Cost Trade Prevention 
 Submitted by VulnViper , also found by 0xAura , 0xDeoGratias , 0xDetermination , 0xhanu58 , 0xPhantom , 0xterrah , Almanax , anonymousjoe , axelot , BenRai , boredpukar , ChainSentry , DDEENNY , dhank , EVDoc , Gosho , guri , jerry0422 , lirezArAzAvi , lodelux , Neeloy , Pexy , random1106 , Riceee , sharonphiliplima , solhhj , Tofu , v2110 , and Zibounne 
 
 clob/CLOB.sol #L503-L505 
 clob/CLOB.sol #L544-L546 
 
 In CLOB.sol , the validation logic incorrectly uses bitwise operations to detect zero-value trades, creating two critical issues:
If baseTokenAmountReceived = 1 and quoteTokenAmountSent = 2, then baseTokenAmountReceived & quoteTokenAmountSent = 0. 
 https://github.com/code-423n4/2025-07-gte-clob/blob/main/contracts/clob/CLOB.sol#L503-L505 
 @> if ( baseTokenAmountReceived != quoteTokenAmountSent && baseTokenAmountReceived & quoteTokenAmountSent == 0 ) { 
 revert ZeroCostTrade (); 
 } 
 https://github.com/code-423n4/2025-07-gte-clob/blob/main/contracts/clob/CLOB.sol#L544-L546 
 @> if ( baseTokenAmountSent != quoteTokenAmountReceived && baseTokenAmountSent & quoteTokenAmountReceived == 0 ) { 
 revert ZeroCostTrade (); 
 } 
 Impact 
 Occurrence Probability:	Low (requires specific value alignment) 
 Operational Impact:	High (instant revert blocks valid trade) 
 Recommended Mitigation Steps 
 - if (baseTokenAmountReceived != quoteTokenAmountSent && baseTokenAmountReceived & quoteTokenAmountSent == 0) { 
 + if (baseTokenAmountReceived != quoteTokenAmountSent && (baseTokenAmountReceived == 0 || quoteTokenAmountSent == 0)) { 
 revert ZeroCostTrade(); 
 } 
 - if (baseTokenAmountSent != quoteTokenAmountReceived && baseTokenAmountSent & quoteTokenAmountReceived == 0) { 
 + if (baseTokenAmountSent != quoteTokenAmountReceived && (baseTokenAmountSent == 0 || quoteTokenAmountReceived == 0)) { 
 revert ZeroCostTrade(); 
 } 
 View detailed Proof of Concept 
 
 [M-02] FOK orders wrongly revert on dust residual amounts below lot size 
 Submitted by montecristo , also found by 0x15 , 0xterrah , Adotsam , ahahaHard1k , Angry_Mustache_Man , anonymousjoe , befree3x , BenRai , boredpukar , dhank , dmdg321 , edoscoba , KineticsOfWeb3 , lodelux , lonelybones , Ollam , Olugbenga , princekay , random1
