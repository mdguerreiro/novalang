% ═══════════════════════════════════════════════════════════════════════════════════════
%  Missing object-level authorization (IDOR, CWE-639): the first non-taint class.
%  A request handler's id parameter selects a record of a per-user model and nothing ties the
%  record to the current user: no query scoped by the user, no owner comparison, no authorizing
%  decorator. Unknown decorators are frontier questions for the oracle.
% ═══════════════════════════════════════════════════════════════════════════════════════

handler(F) :- entry(F).
handler(F) :- decorated(F,D), framework_source(D,_).
handler(F) :- fn_ref(K,I,F), callname(K,Q), registrar(Q,I).
owned_model(M) :- owner_field(M,_).

% Parameter I of F selects a record (here or in a callee).
p2l(F,I,K) :- pr(N,F,I), lookup_dep(K,N), lookup(K,_).
p2l(F,I,K) :- pr(A,F,I), arg_in(X,J,A), call(X,G), p2l(G,J,K).

% Values derived from the current user / from the record (context-insensitive is enough here).
udep(N) :- user_ref(N).
udep(B) :- udep(A), edge(A,B).
udep(Y) :- udep(A), arg_in(Y,J,A), call(Y,G), p2r_raw(G,J).
% rdep is only read by owner_check: values of record K that reach an operand compared with the current user.
% to_cmp (one relation, not per lookup) holds the nodes that can reach such an operand, so per-lookup propagation
% stays on those paths instead of everything the record flows to.
cmp_user(B) :- cmp2(A,B), udep(A).
to_cmp(B) :- cmp_user(B).
to_cmp(A) :- edge(A,B), to_cmp(B).
to_cmp(R) :- ret(G,R), call(Y,G), to_cmp(Y).
to_cmp(A) :- arg_in(X,J,A), call(X,G), param(G,J,P), to_cmp(P).
rdep(K,K) :- lookup(K,_), idor_cand(_,K,_), to_cmp(K).  % only for lookups that are IDOR candidates
rdep(B,K) :- rdep(A,K), edge(A,B), to_cmp(B).
rdep(Y,K) :- rdep(R,K), ret(G,R), call(Y,G), to_cmp(Y).
rdep(P,K) :- rdep(A,K), arg_in(X,J,A), call(X,G), param(G,J,P), to_cmp(P).
udep(P)   :- udep(A), arg_in(X,J,A), call(X,G), param(G,J,P).

cmp2(A,B) :- compare(A,B).
cmp2(A,B) :- compare(B,A).
owner_check(K) :- cmp2(A,B), udep(A), rdep(B,K).

% An owner-like column makes a model a candidate; whether its records are private is a per-model question.
idor_cand(P,K,M) :- handler(F), id_param(F,I), param(F,I,P), p2l(F,I,K), lookup(K,M), owned_model(M), not public_model(M),
                    not test_fn(F).
privacy_frontier(M) :- idor_cand(P,K,M), not idor_safe(P,K), not private_model(M).
idor_mit(P,K,owner_check)  :- idor_cand(P,K,_), owner_check(K).
idor_mit(P,K,scoped_query) :- idor_cand(P,K,_), scoped(K).
idor_mit(P,K,authz(D))     :- idor_cand(P,K,_), node(P,F), decorated(F,D), authz_decorator(D).
idor_safe(P,K) :- idor_mit(P,K,_).

answered_dec(D) :- authz_decorator(D).
answered_dec(D) :- not_authz_decorator(D).
answered_dec(D) :- route_dec(D).
answered_dec(D) :- framework_source(D,_).
authz_frontier(D)       :- idor_cand(P,K,_), not idor_safe(P,K), node(P,F), decorated(F,D), not answered_dec(D).
idor_unknown(P,K,D)     :- idor_cand(P,K,_), node(P,F), decorated(F,D), not answered_dec(D).

cand(P,K,"idor")             :- idor_cand(P,K,_).
mit(P,K,"idor",W)            :- idor_mit(P,K,W).
alarm(P,K,"idor",any)        :- idor_cand(P,K,_), not idor_safe(P,K).
% Authorization often lives outside the handler (middleware, services, row-level security): the engine
% never confirms an IDOR on its own. It proposes candidates; the verifier reads the code around them.
asm(P,K,"idor",unknown_authz(D)) :- alarm(P,K,"idor",any), idor_unknown(P,K,D).
asm(P,K,"idor",unknown_privacy(M)) :- alarm(P,K,"idor",any), idor_cand(P,K,M), not private_model(M).
asm(P,K,"idor",authz_context(F)) :- alarm(P,K,"idor",any), node(P,F).
