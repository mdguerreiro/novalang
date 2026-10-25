% ═══════════════════════════════════════════════════════════════════════════════════════
%  Tier-0 decision layer. Every candidate source→sink flow gets exactly one status.
%  Proof-carrying: a candidate is `mitigated` only when a named mitigation W is derived.
% ═══════════════════════════════════════════════════════════════════════════════════════

mitigated(S,K,C,W)       :- cand(S,K,C), not alarm(S,K,C,any), mit(S,K,C,W).
mitigated(S,K,C,dead(F)) :- cand(S,K,C), node(S,F), dead_fn(F).
mitigated(S,K,C,exposure(F)) :- cand(S,K,C), node(S,F), internal_only(F).
safe(S,K,C)              :- mitigated(S,K,C,_).

test_only(S,K,C)  :- cand(S,K,C), test_node(S), not safe(S,K,C).

open(S,K,C)       :- alarm(S,K,C,any), not safe(S,K,C), not test_only(S,K,C).
has_asm(S,K,C)    :- open(S,K,C), asm(S,K,C,_), not alarm(S,K,C,clean).
has_asm(S,K,C)    :- open(S,K,C), asm(S,K,C,weak_source(_)).
has_asm(S,K,C)    :- open(S,K,C), asm(S,K,C,unreachable(_)).
has_asm(S,K,C)    :- open(S,K,C), asm(S,K,C,authz_context(_)).

undecided(S,K,C)  :- open(S,K,C), has_asm(S,K,C).
confirmed(S,K,C)  :- open(S,K,C), not has_asm(S,K,C).
