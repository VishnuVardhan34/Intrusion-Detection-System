"""
Prototype implementation of SDPD-PHM (Symbolic Derivative-Driven Partial Determinization
with Partitioned Hopcroft Minimization).

Limitations:
- Supports literals, concatenation, alternation (|), Kleene star (*),
  dot (.), and simple character classes ([abc], ranges).
- Predicate partitioning is coarse: characters present in the pattern are
  separate predicates; a single 'OTHER' predicate covers remaining characters.
- Simplification is basic (flattening, removing empty/eplison where possible).
This prototype illustrates the hybrid pipeline and produces a minimized DFA
that can be used for matching and benchmarking against the existing engine.
"""

import sre_parse
from collections import deque, defaultdict

# AST node classes
class EmptySet:
    def __repr__(self): return "Ø"
    def to_tuple(self): return ("EMPTY",)

class Epsilon:
    def __repr__(self): return "ε"
    def to_tuple(self): return ("EPS",)

class Literal:
    def __init__(self, ch): self.ch = ch
    def __repr__(self): return repr(self.ch)
    def to_tuple(self): return ("LIT", self.ch)

class AnyDot:
    def __repr__(self): return "."
    def to_tuple(self): return ("ANY",)

class CharClass:
    def __init__(self, chars): self.chars = frozenset(chars)
    def __repr__(self): return "[" + "".join(sorted(self.chars)) + "]"
    def to_tuple(self): return ("CLASS", tuple(sorted(self.chars)))

class Concat:
    def __init__(self, parts): self.parts = parts
    def __repr__(self): return "·".join(map(repr, self.parts))
    def to_tuple(self): return ("CAT", tuple(p.to_tuple() for p in self.parts))

class Alt:
    def __init__(self, opts): self.opts = opts
    def __repr__(self): return "(" + " | ".join(map(repr, self.opts)) + ")"
    def to_tuple(self): return ("ALT", tuple(o.to_tuple() for o in self.opts))

class Star:
    def __init__(self, node): self.node = node
    def __repr__(self): return "(" + repr(self.node) + ")*"
    def to_tuple(self): return ("STAR", self.node.to_tuple())

# Helpers
def is_empty(x): return isinstance(x, EmptySet)
def is_eps(x): return isinstance(x, Epsilon)

def nullable(node):
    if isinstance(node, Epsilon): return True
    if isinstance(node, EmptySet): return False
    if isinstance(node, Literal): return False
    if isinstance(node, AnyDot): return False
    if isinstance(node, CharClass): return False
    if isinstance(node, Star): return True
    if isinstance(node, Concat):
        for p in node.parts:
            if not nullable(p): return False
        return True
    if isinstance(node, Alt):
        for o in node.opts:
            if nullable(o): return True
        return False
    return False

def simplify(node):
    # basic simplifications: flatten concat/alt, remove empty/eps where possible
    if isinstance(node, Concat):
        parts = []
        for p in node.parts:
            sp = simplify(p)
            if is_empty(sp): return EmptySet()
            if is_eps(sp): continue
            if isinstance(sp, Concat):
                parts.extend(sp.parts)
            else:
                parts.append(sp)
        if not parts: return Epsilon()
        if len(parts) == 1: return parts[0]
        return Concat(parts)
    if isinstance(node, Alt):
        opts = []
        seen = set()
        for o in node.opts:
            so = simplify(o)
            if is_empty(so): continue
            key = repr(so)
            if key in seen: continue
            seen.add(key)
            if isinstance(so, Alt):
                for sub in so.opts:
                    k = repr(sub)
                    if k not in seen:
                        seen.add(k); opts.append(sub)
            else:
                opts.append(so)
        if not opts: return EmptySet()
        # if any option nullable, not simplifying that further here
        if len(opts) == 1: return opts[0]
        return Alt(opts)
    if isinstance(node, Star):
        inner = simplify(node.node)
        if is_empty(inner) or is_eps(inner): return Epsilon()
        if isinstance(inner, Star): return inner
        return Star(inner)
    return node

# Parse limited regex to AST using sre_parse
def parse_pattern(pat):
    parsed = sre_parse.parse(pat)
    def build(sub):
        parts = []
        for tok, val in sub:
            if tok is sre_parse.LITERAL:
                parts.append(Literal(chr(val)))
            elif tok is sre_parse.ANY:
                parts.append(AnyDot())
            elif tok is sre_parse.SUBPATTERN:
                # val = (group, add_flags, del_flags, pattern)
                parts.append(build(val[-1]))
            elif tok is sre_parse.IN:
                chars = set()
                for in_tok, in_val in val:
                    if in_tok is sre_parse.LITERAL:
                        chars.add(chr(in_val))
                    elif in_tok is sre_parse.RANGE:
                        a, b = in_val
                        for c in range(a, b+1): chars.add(chr(c))
                    elif in_tok is sre_parse.NEGATE:
                        # fallback: cannot represent negation precisely here; leave as ANY
                        chars = None; break
                    else:
                        chars = None; break
                if chars is None:
                    parts.append(AnyDot())
                else:
                    parts.append(CharClass(chars))
            elif tok is sre_parse.BRANCH:
                # val = (None, [list_of_subpatterns])
                branches = [build(v) for v in val[1]]
                parts.append(Alt(branches))
            elif tok is sre_parse.MAX_REPEAT:
                minr, maxr, body = val
                if minr == 0 and maxr == sre_parse.MAXREPEAT:
                    parts.append(Star(build(body)))
                else:
                    # expand bounded repeats naively
                    node = build(body)
                    if minr == 0:
                        seq = [Epsilon()]
                    else:
                        seq = [node for _ in range(minr)]
                    if maxr is sre_parse.MAXREPEAT:
                        seq.append(Star(node))
                    else:
                        for _ in range(max(0, maxr-minr)):
                            seq.append(node)
                    parts.append(Concat(seq) if len(seq) >1 else seq[0])
            else:
                # unsupported token -> Any
                parts.append(AnyDot())
        if not parts:
            return Epsilon()
        if len(parts) == 1:
            return parts[0]
        return Concat(parts)
    ast = build(parsed)
    return simplify(ast)

# derivative (Brzozowski)
def derivative(node, ch):
    if isinstance(node, EmptySet): return EmptySet()
    if isinstance(node, Epsilon): return EmptySet()
    if isinstance(node, Literal): return Epsilon() if node.ch == ch else EmptySet()
    if isinstance(node, AnyDot): return Epsilon()
    if isinstance(node, CharClass): return Epsilon() if ch in node.chars else EmptySet()
    if isinstance(node, Alt):
        return simplify(Alt([derivative(o, ch) for o in node.opts]))
    if isinstance(node, Concat):
        first, rest = node.parts[0], node.parts[1:]
        d_first = derivative(first, ch)
        if rest:
            rest_node = Concat(rest) if len(rest) > 1 else rest[0]
            part1 = simplify(Concat([d_first, rest_node])) if not is_empty(d_first) else EmptySet()
            if nullable(first):
                part2 = derivative(rest_node, ch)
                return simplify(Alt([part1, part2]))
            else:
                return simplify(part1)
        else:
            return simplify(d_first)
    if isinstance(node, Star):
        d = derivative(node.node, ch)
        return simplify(Concat([d, node]))
    return EmptySet()

# Predicate partition: chars explicitly used in pattern + OTHER
def compute_predicates(ast):
    used = set()
    def collect(n):
        if isinstance(n, Literal): used.add(n.ch)
        elif isinstance(n, CharClass): used.update(n.chars)
        elif isinstance(n, Concat):
            for p in n.parts: collect(p)
        elif isinstance(n, Alt):
            for o in n.opts: collect(o)
        elif isinstance(n, Star):
            collect(n.node)
    collect(ast)
    # limit to printable ASCII for prototype (common case)
    preds = []
    for c in sorted(used):
        preds.append(f"'{c}'")
    preds.append("OTHER")
    return preds

# Representative char for a predicate (for derivative computation)
def pick_representative(pred, used_set):
    if pred == "OTHER":
        # pick a char not in used_set (simple choice)
        for i in range(32, 127):
            ch = chr(i)
            if ch not in used_set:
                return ch
        return '\0'
    # pred like "'a'"
    return pred.strip("'")

# Build lazy DFA via derivatives and minimize with Hopcroft
class HybridDFA:
    def __init__(self, pattern, max_states=10000):
        self.pattern = pattern
        self.ast = parse_pattern(pattern)
        self.predicates = compute_predicates(self.ast)
        self.used_chars = set([p.strip("'") for p in self.predicates if p != "OTHER"])
        self.max_states = max_states
        # states: map from repr(tuple) to id and AST
        self.state_map = {}
        self.states = []
        self.transitions = {}  # (sid, pred) -> sid2
        self.accepting = set()
        self.build_partial()
        self.minimize()

    def _add_state(self, ast_node):
        key = ast_node.to_tuple()
        if key in self.state_map:
            return self.state_map[key]
        sid = len(self.states)
        self.state_map[key] = sid
        self.states.append(ast_node)
        if nullable(ast_node):
            self.accepting.add(sid)
        return sid

    def build_partial(self):
        # BFS lazy determinization
        initial = self.ast
        q = deque()
        s0 = self._add_state(initial)
        q.append(s0)
        while q and len(self.states) < self.max_states:
            sid = q.popleft()
            node = self.states[sid]
            for pred in self.predicates:
                rep = pick_representative(pred, self.used_chars)
                nxt_ast = simplify(derivative(node, rep))
                nid = self._add_state(nxt_ast)
                self.transitions[(sid, pred)] = nid
                if nid >= len(self.states)-1:  # newly added
                    q.append(nid)
        # any missing transitions lead to EmptySet state
        empty_sid = self._add_state(EmptySet())
        for sid in range(len(self.states)):
            for pred in self.predicates:
                if (sid, pred) not in self.transitions:
                    self.transitions[(sid, pred)] = empty_sid

    def minimize(self):
        # Hopcroft minimization
        Q = set(range(len(self.states)))
        F = set(self.accepting)
        nonF = Q - F
        P = [F, nonF] if nonF else [F]
        W = deque([blk for blk in P if blk])
        # build inverse map: for pred, map tgt -> set(src)
        inv = {pred: defaultdict(set) for pred in self.predicates}
        for (s, pred), t in self.transitions.items():
            inv[pred][t].add(s)
        while W:
            A = W.popleft()
            for pred in self.predicates:
                # X = predecessors of A under pred
                X = set()
                for a_state in A:
                    X |= inv[pred].get(a_state, set())
                if not X:
                    continue
                newP = []
                for Y in P:
                    inter = Y & X
                    diff = Y - X
                    if inter and diff:
                        newP.append(inter)
                        newP.append(diff)
                        # replace Y by inter and diff; update worklist
                        if Y in W:
                            W.remove(Y)
                            W.append(inter); W.append(diff)
                        else:
                            if len(inter) <= len(diff):
                                W.append(inter)
                            else:
                                W.append(diff)
                    else:
                        newP.append(Y)
                P = newP
        # build representative mapping
        self.block_of = {}
        for i, blk in enumerate(P):
            for s in blk:
                self.block_of[s] = i
        # construct minimized transitions
        self.min_states = {}
        for s in Q:
            b = self.block_of[s]
            self.min_states.setdefault(b, len(self.min_states))
        self.start = self.block_of[0]
        self.min_trans = {}
        self.min_accepting = set()
        for s in Q:
            b = self.block_of[s]
            if b not in self.min_trans:
                self.min_trans[b] = {}
            for pred in self.predicates:
                t = self.transitions[(s, pred)]
                tb = self.block_of[t]
                self.min_trans[b][pred] = tb
            if s in self.accepting:
                self.min_accepting.add(b)

    def _pred_for_char(self, ch):
        if ch in self.used_chars:
            return f"'{ch}'"
        return "OTHER"

    def match(self, text):
        # run minimized DFA
        s = self.start
        for ch in text:
            pred = self._pred_for_char(ch)
            s = self.min_trans.get(s, {}).get(pred, None)
            if s is None:
                return False
        return s in self.min_accepting

# simple CLI demo if run as script
if __name__ == "__main__":
    examples = [
        r"(a|b)*abb",
        r"SELECT .* FROM .* WHERE .*",
        r"(<script>.*</script>)|javascript:.*"
    ]
    for pat in examples:
        print("Pattern:", pat)
        dfa = HybridDFA(pat, max_states=5000)
        print("States:", len(dfa.states), "Min states:", len(dfa.min_trans))
        tests = ["abb", "aabb", "ab", "SELECT name FROM users WHERE id=1", "<script>alert(1)</script>"]
        for t in tests:
            print(" ", repr(t), "->", dfa.match(t))
        print()