% ═══════════════════════════════════════════════════════════════════════════════════════
%  Sentinel taint analysis — stratified Datalog (evaluated by clingo).
%
%  Taint is tracked per (source S, vulnerability class C, mode M):
%    M = any    every path, including paths through assumption points;
%    M = clean  only paths that pass no assumption point (unknown API, unknown guard, ...).
%  Sanitizers are class-specific: kill(N, C, Why) stops C-taint at node N.
%  Calls to project functions are composed through parameter summaries, so call/return
%  pairs are matched (no flow from one caller's argument into another caller's result).
% ═══════════════════════════════════════════════════════════════════════════════════════

mode(any). mode(clean).

% ── sanitisation (class-specific; `all` expands to every class) ─────────────────────────
kill(N,C,W)          :- san(N,C,W), cls(C).
kill(N,C,W)          :- san(N,"all",W), cls(C).
kill(N,C,api(Q))     :- callname(N,Q), sanitizer_api(Q,C), cls(C).
kill(N,C,api(Q))     :- callname(N,Q), sanitizer_api(Q,"all"), cls(C).
kill(G,C,guard(P))   :- guard(G,P), safe_pred(P,C), cls(C).
kill(G,C,guard(P))   :- guard(G,P), safe_pred(P,"all"), cls(C).
kill(N,C,type(T))    :- typed(N,T), safe_type(T,C), cls(C).
kill(N,C,type(T))    :- typed(N,T), safe_type(T,"all"), cls(C).
killed(N,C)          :- kill(N,C,_).

% ── assumption points: steps whose security semantics are not modelled ─────────────────
modeled_node(N)      :- san(N,_,_).
modeled_node(N)      :- src(N,_).
modeled_node(N)      :- sink(N,_).
modeled_api(Q)       :- propagator_api(Q).
modeled_api(Q)       :- sanitizer_api(Q,_).
known_pred(P)        :- safe_pred(P,_).
known_pred(P)        :- not_safe_pred(P).
assume_at(N,unknown_api(Q))     :- libcall(N,Q), not modeled_node(N), not modeled_api(Q).
assume_at(G,unknown_guard(P))   :- guard(G,P), not known_pred(P).
assume_at(N,maybe_sanitizer(F)) :- call(N,F), sanitizer_like(F), not sanitizer_api(F,_), not not_sanitizer(F).
blocked(N,clean)     :- assume_at(N,_).

% ── parameter summaries ─────────────────────────────────────────────────────────────────
% pc(N,F,I,C,M): node N in F carries parameter I, still dangerous for class C.
% Demand-driven: class/mode summaries only for functions that tainted data can reach as an argument
% (directly or through callees). Raw summaries (pr) stay total: they are cheap and feed traw and the frontier.
needed(G) :- traw(A,_), arg_in(K,_,A), call(K,G).
needed(G) :- needed(F), node(X,F), call(X,G).
pc(P,F,I,C,M) :- param(F,I,P), needed(F), cls(C), mode(M), not killed(P,C), not blocked(P,M).
pc(B,F,I,C,M) :- pc(A,F,I,C,M), edge(A,B), not killed(B,C), not blocked(B,M).
pc(K,F,I,C,M) :- pc(A,F,I,C,M), arg_in(K,J,A), call(K,G), p2r(G,J,C,M), not killed(K,C), not blocked(K,M).
p2r(F,I,C,M)   :- pc(R,F,I,C,M), ret(F,R).
p2s(F,I,K,C,M) :- pc(K,F,I,C,M), sink(K,C).
p2s(F,I,K,C,M) :- pc(A,F,I,C,M), arg_in(X,J,A), call(X,G), p2s(G,J,K,C,M).

% Raw summaries ignore sanitisers and assumptions: they define *candidates*.
pr(P,F,I)      :- param(F,I,P).
pr(B,F,I)      :- pr(A,F,I), edge(A,B).
pr(K,F,I)      :- pr(A,F,I), arg_in(K,J,A), call(K,G), p2r_raw(G,J).
p2r_raw(F,I)   :- pr(R,F,I), ret(F,R).
p2s_raw(F,I,K) :- pr(K,F,I), sink(K,_).
p2s_raw(F,I,K) :- pr(A,F,I), arg_in(X,J,A), call(X,G), p2s_raw(G,J,K).

% Kill summaries: parameter I's C-danger was neutralised by W before reaching N.
pk(P,F,I,C,W) :- param(F,I,P), kill(P,C,W).
pk(B,F,I,C,W) :- pc(A,F,I,C,any), edge(A,B), kill(B,C,W).
pk(B,F,I,C,W) :- pk(A,F,I,C,W), edge(A,B).
pk(K,F,I,C,W) :- pk(A,F,I,C,W), arg_in(K,J,A), call(K,G), p2r_raw(G,J).
pk(K,F,I,C,W) :- pc(A,F,I,C,any), arg_in(K,J,A), call(K,G), p2k_r(G,J,C,W).
pk(K,F,I,C,W) :- pc(A,F,I,C,any), arg_in(K,J,A), call(K,G), p2r(G,J,C,any), kill(K,C,W).
p2k_r(F,I,C,W)   :- pk(R,F,I,C,W), ret(F,R).
p2k_s(F,I,K,C,W) :- pk(K,F,I,C,W), sink(K,C).
p2k_s(F,I,K,C,W) :- pk(A,F,I,C,W), arg_in(X,J,A), call(X,G), p2s_raw(G,J,K), sink(K,C).
p2k_s(F,I,K,C,W) :- pc(A,F,I,C,any), arg_in(X,J,A), call(X,G), p2k_s(G,J,K,C,W).

% Assumption summaries: parameter I reaches N (dangerous for C) through assumption Asm.
% Only for parameter paths that matter (reach a sink or the return value): the two places pa is consumed.
pa_need(F,I,C) :- p2s(F,I,_,C,any).
pa_need(F,I,C) :- p2r(F,I,C,any).
pa(N,F,I,C,Asm) :- pc(N,F,I,C,any), assume_at(N,Asm), pa_need(F,I,C).
pa(B,F,I,C,Asm) :- pa(X,F,I,C,Asm), edge(X,B), pc(B,F,I,C,any).
pa(K,F,I,C,Asm) :- pa(X,F,I,C,Asm), arg_in(K,J,X), call(K,G), p2r(G,J,C,any), pc(K,F,I,C,any).
pa(K,F,I,C,Asm) :- pc(X,F,I,C,any), arg_in(K,J,X), call(K,G), p2a_r(G,J,C,Asm), pc(K,F,I,C,any).
p2a_r(F,I,C,Asm)   :- pa(R,F,I,C,Asm), ret(F,R).
p2a_s(F,I,K,C,Asm) :- pa(K,F,I,C,Asm), sink(K,C).
p2a_s(F,I,K,C,Asm) :- pa(X,F,I,C,Asm), arg_in(Y,J,X), call(Y,G), p2s(G,J,K,C,any).
p2a_s(F,I,K,C,Asm) :- pc(X,F,I,C,any), arg_in(Y,J,X), call(Y,G), p2a_s(G,J,K,C,Asm).

% ── source propagation ──────────────────────────────────────────────────────────────────
traw(S,S) :- src(S,_).
traw(B,S) :- traw(A,S), edge(A,B).
traw(K,S) :- traw(A,S), arg_in(K,J,A), call(K,G), p2r_raw(G,J).
traw(K,S) :- call(K,G), ret(G,R), traw(R,S).

t(S,S,C,M) :- src(S,_), cls(C), mode(M), not killed(S,C), not blocked(S,M).
t(B,S,C,M) :- t(A,S,C,M), edge(A,B), not killed(B,C), not blocked(B,M).
t(K,S,C,M) :- t(A,S,C,M), arg_in(K,J,A), call(K,G), p2r(G,J,C,M), not killed(K,C), not blocked(K,M).
t(K,S,C,M) :- call(K,G), ret(G,R), t(R,S,C,M), not killed(K,C), not blocked(K,M).

tk(S,S,C,W) :- src(S,_), kill(S,C,W).
tk(B,S,C,W) :- t(A,S,C,any), edge(A,B), kill(B,C,W).
tk(B,S,C,W) :- tk(A,S,C,W), edge(A,B).
tk(K,S,C,W) :- tk(A,S,C,W), arg_in(K,J,A), call(K,G), p2r_raw(G,J).
tk(K,S,C,W) :- t(A,S,C,any), arg_in(K,J,A), call(K,G), p2k_r(G,J,C,W).
tk(K,S,C,W) :- t(A,S,C,any), arg_in(K,J,A), call(K,G), p2r(G,J,C,any), kill(K,C,W).
tk(K,S,C,W) :- call(K,G), ret(G,R), tk(R,S,C,W).
tk(K,S,C,W) :- call(K,G), ret(G,R), t(R,S,C,any), kill(K,C,W).

ta(N,S,C,Asm) :- t(N,S,C,any), assume_at(N,Asm).
ta(B,S,C,Asm) :- ta(X,S,C,Asm), edge(X,B), t(B,S,C,any).
ta(K,S,C,Asm) :- ta(X,S,C,Asm), arg_in(K,J,X), call(K,G), p2r(G,J,C,any), t(K,S,C,any).
ta(K,S,C,Asm) :- t(X,S,C,any), arg_in(K,J,X), call(K,G), p2a_r(G,J,C,Asm), t(K,S,C,any).
ta(K,S,C,Asm) :- call(K,G), ret(G,R), ta(R,S,C,Asm), t(K,S,C,any).

% ── findings ────────────────────────────────────────────────────────────────────────────
cand(S,K,C) :- traw(K,S), sink(K,C).
cand(S,K,C) :- traw(A,S), arg_in(X,J,A), call(X,G), p2s_raw(G,J,K), sink(K,C).

alarm(S,K,C,M) :- t(K,S,C,M), sink(K,C).
alarm(S,K,C,M) :- t(A,S,C,M), arg_in(X,J,A), call(X,G), p2s(G,J,K,C,M).

mit(S,K,C,W) :- tk(K,S,C,W), sink(K,C).
mit(S,K,C,W) :- tk(A,S,C,W), arg_in(X,J,A), call(X,G), p2s_raw(G,J,K), sink(K,C).
mit(S,K,C,W) :- t(A,S,C,any), arg_in(X,J,A), call(X,G), p2k_s(G,J,K,C,W).

asm(S,K,C,Asm) :- ta(K,S,C,Asm), sink(K,C).
asm(S,K,C,Asm) :- ta(X,S,C,Asm), arg_in(Y,J,X), call(Y,G), p2s(G,J,K,C,any).
asm(S,K,C,Asm) :- t(X,S,C,any), arg_in(Y,J,X), call(Y,G), p2a_s(G,J,K,C,Asm).

reach(F) :- entry(F).
reach(F) :- entry_source(F,_,_).
reach(F) :- decorated(F,D), framework_source(D,_).
reach(F) :- fn_ref(K,I,F), callname(K,Q), registrar(Q,I).
reach(G) :- reach(F), node(X,F), call(X,G).
asm(S,K,C,weak_source(Kd)) :- alarm(S,K,C,any), src(S,Kd), weak_kind(Kd).
asm(S,K,C,unreachable(F))  :- alarm(S,K,C,any), node(S,F), not reach(F), not test_node(S), not dead_fn(F).

% ── learned specifications: frontier answers turned into facts ─────────────────────────
% A library API learned to be a sink for class C at argument position/keyword I.
sink(A,C)          :- lib_arg(K,I,A), callname(K,Q), sink_api(Q,I,C), cls(C).
learned_sink(A,Q)  :- lib_arg(K,I,A), callname(K,Q), sink_api(Q,I,_).
modeled_api(Q)     :- sink_api(Q,_,_).
% Functions registered with a framework decorator learned to deliver request data, or a specific
% entrypoint parameter learned to be attacker-controlled (e.g. an AWS Lambda event).
src(P,K)           :- decorated(F,D), framework_source(D,K), param(F,_,P), not self_param(P).
src(P,K)           :- entry_source(F,I,K), param(F,I,P).
learned_src(P,D)   :- decorated(F,D), framework_source(D,_), param(F,_,P).
learned_src(P,F)   :- entry_source(F,I,_), param(F,I,P).

% ── the taint frontier: where tainted data meets something the engine does not understand ──
answered_api(Q)    :- modeled_api(Q).
answered_api(Q)    :- not_sink_api(Q).
answered_api(Q)    :- propagator_api(Q).
answered_api(Q)    :- sanitizer_api(Q,_).
% A caller that takes no parameters (`_local_test()`, `main()`) cannot feed F external input: F is still a root.
has_caller(F)      :- call(X,F), node(X,H), param(H,_,_).
spec_call(K)       :- lib_arg(K,_,A), sink(A,_).
spec_call(K)       :- modeled_node(K).
sink_frontier(Q,I) :- lib_arg(K,I,A), traw(A,_), libcall(K,Q), not answered_api(Q), not spec_call(K), not generic_api(Q).

answered_entry(F)  :- not_entry(F).
answered_entry(F)  :- entry_source(F,_,_).
answered_entry(F)  :- decorated(F,D), framework_source(D,_).
answered_entry(F)  :- decorated(F,D), not_framework_source(D).
has_src_param(F)   :- param(F,_,P), src(P,_).
src_frontier(F,I)  :- entry(F), param(F,I,P), p2s_raw(F,I,_), not has_src_param(F), not typed(P,_), not answered_entry(F).
src_frontier(F,I)  :- param(F,I,P), p2s_raw(F,I,_), not reach(F), not has_caller(F), not test_fn(F), not typed(P,_), not answered_entry(F), not pending_reg(F).

% Handlers registered by passing the function to a framework call (`app.router.add_route("GET", "/", view)`):
% one question about the registrar covers every handler it registers.
src(P,"http")      :- fn_ref(K,I,F), callname(K,Q), registrar(Q,I), param(F,_,P), not typed(P,_), not self_param(P).
learned_src(P,Q)   :- fn_ref(K,I,F), callname(K,Q), registrar(Q,I), param(F,_,P).
answered_reg(Q)    :- registrar(Q,_).
answered_reg(Q)    :- not_registrar(Q).
pending_reg(F)     :- fn_ref(K,_,F), callname(K,Q), not answered_reg(Q).
% Asked even when no known sink is reachable yet: unknown framework + unknown sink is the common case, and
% there are only a handful of registrar APIs per code base.
reg_frontier(Q,I)  :- fn_ref(K,I,F), callname(K,Q), param(F,_,_), not has_caller(F), not answered_reg(Q), not test_fn(F),
                      not generic_reg(Q), not test_node(K).
answered_entry(F)  :- fn_ref(K,I,F), callname(K,Q), registrar(Q,I).

% Route-shaped decorators (`app.get`, `router.post`, `bp.route`) are asked about even before a known sink is
% reachable: an unknown framework plus an unknown sink is common, and there are few such decorators.
dec_frontier(D) :- decorated(F,D), route_dec(D), param(F,_,_), not answered_dec_src(D), not test_fn(F).
answered_dec_src(D) :- framework_source(D,_).
answered_dec_src(D) :- not_framework_source(D).

% Sources from library reads (`flask.request.args`, `bottle.request.query`, `event_bus.receive()`): the mirror of
% the sink frontier. A library call or attribute whose value reaches a sink while nothing upstream is a known
% source is asked about once ("is this attacker-controlled?"); the answer is a global source_api fact.
src(N,K) :- attrname(N,Q), source_api(Q,K).
src(N,K) :- callname(N,Q), source_api(Q,K), not lib_input(N).
learned_src(N,Q) :- attrname(N,Q), source_api(Q,_).
learned_src(N,Q) :- callname(N,Q), source_api(Q,_), not lib_input(N).
lib_input(N) :- lib_arg(N,_,_).
rs(N) :- sink(N,_).
rs(A) :- edge(A,B), rs(B).
rs(A) :- arg_in(X,J,A), call(X,G), p2s_raw(G,J,_).
rs(R) :- ret(G,R), call(K,G), rs(K).
answered_src(Q) :- source_api(Q,_).
answered_src(Q) :- not_source_api(Q).
answered_src(Q) :- sink_api(Q,_,_).
srcapi_frontier(Q) :- attrname(N,Q), rs(N), not traw(N,_), not answered_src(Q), node(N,F), not test_fn(F).
srcapi_frontier(Q) :- callname(N,Q), not call(N,_), not spec_call(N), rs(N), not traw(N,_), not lib_input(N),
                      not answered_src(Q), not generic_api(Q), node(N,F), not test_fn(F).
% Seed for "unknown source + unknown sink": library values read inside a route-shaped handler are asked about
% directly (bounded: request objects, app config, globals), so either side can be learned first.
handler_has_src(F) :- traw(N,_), node(N,F).
srcapi_frontier(Q) :- attrname(N,Q), node(N,F), decorated(F,D), route_dec(D), not answered_src(Q), not test_fn(F),
                      not handler_has_src(F).
srcapi_frontier(Q) :- callname(N,Q), node(N,F), decorated(F,D), route_dec(D), not call(N,_), not lib_input(N),
                      not answered_src(Q), not generic_api(Q), not test_fn(F), not spec_call(N), not handler_has_src(F).
