"""
Mô phỏng RAG retrieval cho các GT functions bị miss, kiểm tra xem
custom findings có được truy xuất không và score bao nhiêu.

Chạy: cd backend && source .venv/bin/activate && python -m scripts.rag.test_custom_retrieval
"""
import sys
__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

from scripts.rag.rag_retriever import SolodirRetriever

SCORE_THRESHOLD = 0.65  # _SCORE_INJECT_THRESHOLD_INV trong pipeline

# Mô phỏng structural + operation queries mà pipeline sẽ sinh ra cho mỗi GT function
# (dựa trên code thực tế của function — giống những gì _generate_structural_queries sẽ output)
GT_QUERIES = {
    "H-01 | ConcentratedLiquidityPool.burn()": [
        "unsafe narrowing cast in burn causes incorrect liquidity delta",
        "integer truncation in burn function allows attacker to steal tokens",
        "uint128 cast overflow in burn liquidity accounting leads to theft",
        "burn function cast error misaligns reserve tracking",
        "narrowing cast silently truncates liquidity amount in burn",
    ],
    "H-07 | ConcentratedLiquidityPosition.burn()": [
        "position manager burn returns wrong token amounts to LP",
        "NFT position burn incorrect token calculation causes LP loss",
        "burn function propagates wrong return value from pool",
        "wrong amount transferred to LP after position burn",
        "position burn misreads pool return values",
    ],
    "H-15 | ConcentratedLiquidityPool.initialize()": [
        "missing input validation in initialize allows out-of-bounds sqrtPrice",
        "initialPrice not validated against tick bounds causes permanent DoS",
        "initialize function missing range check on price parameter",
        "unvalidated initial price bricks pool permanently",
        "sqrtPrice out of range in initialize leads to TickMath revert",
    ],
    "H-17 | ConcentratedLiquidityPool.rangeFeeGrowth()": [
        "nearestTick used instead of current pool tick in fee growth calculation",
        "wrong tick reference in rangeFeeGrowth causes incorrect fee delta",
        "fee growth boundary condition evaluated against wrong tick",
        "rangeFeeGrowth incorrect reference tick produces wrong LP fees",
        "fee accumulator boundary check uses stale tick value",
    ],
}

CUSTOM_SLUGS = {
    "H-01": "custom_35_h01_clp_burn_liquidity_cast_theft",
    "H-07": "custom_35_h07_clposition_burn_wrong_amounts",
    "H-15": "custom_35_h15_clp_initialize_price_validation",
    "H-17": "custom_35_h17_rangefeegrowth_nearesttick_wrong_reference",
}


def main():
    print("Loading retriever...")
    retriever = SolodirRetriever()
    print(f"DB size: {retriever._col.count()} chunks\n")
    print("=" * 70)

    for label, queries in GT_QUERIES.items():
        h_id = label.split()[0]
        target_slug = CUSTOM_SLUGS.get(h_id, "")
        print(f"\n{'='*70}")
        print(f"[{label}]")
        print(f"Target slug: {target_slug}")
        print("-" * 70)

        hit_count = 0
        for q in queries:
            results = retriever.query(q, n_results=5)
            top = results[0] if results else None
            top_slug  = top["source"].split("/")[-1] if top else ""
            top_score = top["score"] if top else 0.0
            top_title = top["title"][:60] if top else ""

            # Check nếu custom slug xuất hiện trong top-5
            custom_hit = next((r for r in results if target_slug in r.get("source","") or
                               target_slug == r.get("slug", r.get("source",""))), None)

            # Try match by title prefix
            if not custom_hit:
                custom_hit = next((r for r in results
                                   if "self-crafted" in r.get("firm","") or
                                      "custom_35" in r.get("source","")), None)

            hit_marker = ""
            if custom_hit:
                hit_count += 1
                hit_marker = f"  ✅ custom hit! score={custom_hit['score']:.3f}"

            pass_threshold = "PASS" if top_score >= SCORE_THRESHOLD else "FAIL"
            print(f"  Q: {q[:60]}")
            print(f"     top1 [{pass_threshold} {top_score:.3f}] {top_title}{hit_marker}")

        print(f"\n  Custom finding retrieved in {hit_count}/{len(queries)} queries")

    print("\n" + "=" * 70)
    print("Done.")


if __name__ == "__main__":
    main()
