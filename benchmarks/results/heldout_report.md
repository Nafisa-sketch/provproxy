# Held-Out Adversarial Robustness Report (A-M)

Seed: 9999
Total cases: 318

## A_fragment_size
Correct: 110/110 (100.0%)
Matched: 110/110
Enforcement-blocked: 110/110

## B_reordered_fragments
Correct: 20/20 (100.0%)
Matched: 20/20
Enforcement-blocked: 20/20

## C_unequal_fragmentation
Correct: 20/20 (100.0%)
Matched: 20/20
Enforcement-blocked: 20/20

## D_duplicate_evidence
Correct: 10/10 (100.0%)
Matched: 0/10
Enforcement-blocked: 0/10

## E_interleaving
Correct: 10/10 (100.0%)
Matched: 10/10
Enforcement-blocked: 10/10
Benign interleaved calls matched: 0/40
Benign interleaved calls blocked: 0/40

## F_destination_isolation
Correct: 10/10 (100.0%)
Matched: 0/10
Enforcement-blocked: 0/10

## G_session_isolation
Correct: 10/10 (100.0%)
Matched: 0/10
Enforcement-blocked: 0/10

## H_ttl_inside_window
Correct: 3/3 (100.0%)
Matched: 3/3
Enforcement-blocked: 3/3

## H_ttl_expired_evidence_excluded
Correct: 3/3 (100.0%)
Matched: 0/3
Enforcement-blocked: 0/3

## I_transform_fragment
Correct: 32/32 (100.0%)
Matched: 32/32
Enforcement-blocked: 32/32

## J_nested_json
Correct: 15/15 (100.0%)
Matched: 15/15
Enforcement-blocked: 15/15

## K_partial_exfiltration
Correct: 20/20 (100.0%)
Matched: 20/50
Enforcement-blocked: 20/50
- fraction=0.10: 0/10 matched
- fraction=0.25: 0/10 matched
- fraction=0.50: 0/10 matched
- fraction=0.75: 10/10 matched
- fraction=1.00: 10/10 matched

## L_multiple_sources
Correct: 10/10 (100.0%)
Matched: 10/10
Enforcement-blocked: 10/10

## M_common_substring_hard_negative
Correct: 15/15 (100.0%)
Matched: 0/15
Enforcement-blocked: 0/15

## A. Detection by chunk size
- chunk_size=2: 10/10
- chunk_size=3: 10/10
- chunk_size=4: 10/10
- chunk_size=5: 10/10
- chunk_size=6: 10/10
- chunk_size=7: 10/10
- chunk_size=8: 10/10
- chunk_size=9: 10/10
- chunk_size=10: 10/10
- chunk_size=11: 10/10
- chunk_size=12: 10/10