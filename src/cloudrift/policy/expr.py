"""A safe expression evaluator for policies.

Expressions are parsed with :func:`ast.parse` in eval mode and checked against
an explicit node and name whitelist. Evaluation walks the checked syntax tree
directly. The ``eval``/``exec`` builtins are never used, and attribute access
only reads keys from plain dictionaries, so policy text cannot reach Python
objects, imports, files, or the network.

Limits:

* ``MAX_NODES`` bounds expression size.
* ``MAX_DEPTH`` bounds syntactic nesting.
* ``MAX_STEPS`` bounds runtime work per policy/resource evaluation.
* Attribute names starting with ``_`` are rejected outright.
"""

from __future__ import annotations

import ast
import operator
from collections.abc import Mapping
from typing import Any

from cloudrift.policy.builtins import FUNCTIONS

MAX_NODES = 500
MAX_DEPTH = 40
MAX_STEPS = 100_000
MAX_COMPREHENSION_GENERATORS = 4
ALLOWED_ROOTS = frozenset({"resource", "related"}) | frozenset(FUNCTIONS)

_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
}
_UNARY_OPS = {ast.Not: operator.not_, ast.USub: operator.neg, ast.UAdd: operator.pos}
_COMPARE_OPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda left, right: left in right,
    ast.NotIn: lambda left, right: left not in right,
}
_MAX_SEQUENCE = 1_000_000


class ExpressionError(Exception):
    """Base error for invalid, unsafe, or failed policy expressions."""


class UnsafeExpression(ExpressionError):
    """Raised when an expression uses syntax outside the whitelist."""


class EvaluationError(ExpressionError):
    """Raised when a safe expression cannot be evaluated."""


def compile_expression(source: str) -> ast.Expression:
    """Parse and validate a policy expression, returning its AST."""

    if not isinstance(source, str) or not source.strip():
        raise UnsafeExpression("expression must be a non-empty string")
    try:
        tree = ast.parse(source, mode="eval")
    except SyntaxError as exc:
        detail = exc.msg or "syntax error"
        raise UnsafeExpression(f"invalid expression syntax: {detail}") from exc
    _Validator().validate(tree)
    return tree


class _Validator:
    def __init__(self) -> None:
        self.count = 0

    def validate(self, node: ast.AST) -> None:
        self._check(node, depth=0, bound=frozenset())

    def _fail(self, message: str) -> None:
        raise UnsafeExpression(message)

    def _enter(self, node: ast.AST, depth: int) -> None:
        if depth > MAX_DEPTH:
            self._fail(f"expression nesting exceeds the maximum depth of {MAX_DEPTH}")
        self.count += 1
        if self.count > MAX_NODES:
            self._fail(f"expression exceeds the maximum size of {MAX_NODES} AST nodes")

    def _check(self, node: ast.AST, depth: int, bound: frozenset[str]) -> None:
        self._enter(node, depth)
        if isinstance(node, ast.Expression):
            self._check(node.body, depth + 1, bound)
        elif isinstance(node, ast.Constant):
            if not isinstance(node.value, (str, int, float, bool, type(None))):
                self._fail(f"constant of type {type(node.value).__name__} is not allowed")
        elif isinstance(node, ast.Name):
            if node.id.startswith("_"):
                self._fail(f"name {node.id!r} is not allowed")
            if node.id not in ALLOWED_ROOTS and node.id not in bound:
                self._fail(
                    f"unknown name {node.id!r}; only 'resource', 'related', "
                    "comprehension variables and whitelisted functions are available"
                )
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("_"):
                self._fail(f"access to private attribute {node.attr!r} is not allowed")
            self._check(node.value, depth + 1, bound)
        elif isinstance(node, ast.Subscript):
            if (
                isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, str)
                and node.slice.value.startswith("_")
            ):
                self._fail("access to private keys is not allowed")
            self._check(node.value, depth + 1, bound)
            self._check(node.slice, depth + 1, bound)
        elif isinstance(node, ast.Slice):
            for part in (node.lower, node.upper, node.step):
                if part is not None:
                    self._check(part, depth + 1, bound)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            if not node.elts:
                return
            for element in node.elts:
                if isinstance(element, ast.Starred):
                    self._fail("starred expressions are not allowed")
                self._check(element, depth + 1, bound)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if key is None:
                    self._fail("dictionary unpacking is not allowed")
                self._check(key, depth + 1, bound)
                self._check(value, depth + 1, bound)
        elif isinstance(node, ast.BinOp):
            if type(node.op) not in _BIN_OPS:
                self._fail(f"operator {type(node.op).__name__} is not allowed")
            self._check(node.left, depth + 1, bound)
            self._check(node.right, depth + 1, bound)
        elif isinstance(node, ast.UnaryOp):
            if type(node.op) not in _UNARY_OPS:
                self._fail(f"operator {type(node.op).__name__} is not allowed")
            self._check(node.operand, depth + 1, bound)
        elif isinstance(node, ast.BoolOp):
            if not isinstance(node.op, (ast.And, ast.Or)):
                self._fail(f"boolean operator {type(node.op).__name__} is not allowed")
            if not node.values:
                self._fail("empty boolean expression")
            for value in node.values:
                self._check(value, depth + 1, bound)
        elif isinstance(node, ast.Compare):
            for op in node.ops:
                if type(op) not in _COMPARE_OPS and not isinstance(op, (ast.Is, ast.IsNot)):
                    self._fail(f"comparison {type(op).__name__} is not allowed")
            self._check(node.left, depth + 1, bound)
            for comparator in node.comparators:
                self._check(comparator, depth + 1, bound)
        elif isinstance(node, ast.IfExp):
            self._check(node.test, depth + 1, bound)
            self._check(node.body, depth + 1, bound)
            self._check(node.orelse, depth + 1, bound)
        elif isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                self._fail("only whitelisted functions may be called by name")
            if node.func.id not in FUNCTIONS:
                self._fail(f"call to non-whitelisted function {node.func.id!r}")
            for arg in node.args:
                if isinstance(arg, ast.Starred):
                    self._fail("starred arguments are not allowed")
                self._check(arg, depth + 1, bound)
            for keyword in node.keywords:
                if keyword.arg is None:
                    self._fail("dictionary keyword arguments are not allowed")
                if keyword.arg.startswith("_"):
                    self._fail(f"keyword argument {keyword.arg!r} is not allowed")
                self._check(keyword.value, depth + 1, bound)
        elif isinstance(node, ast.ListComp | ast.GeneratorExp):
            self._check_comprehension(node, depth, bound)
        else:
            self._fail(f"unsupported syntax: {type(node).__name__}")

    def _check_comprehension(
        self, node: ast.ListComp | ast.GeneratorExp, depth: int, bound: frozenset[str]
    ) -> None:
        if len(node.generators) > MAX_COMPREHENSION_GENERATORS:
            self._fail(
                f"comprehension has too many generators (maximum {MAX_COMPREHENSION_GENERATORS})"
            )
        scope = bound
        for generator in node.generators:
            if generator.is_async:
                self._fail("asynchronous comprehensions are not allowed")
            self._check(generator.iter, depth + 1, scope)
            names = self._target_names(generator.target)
            scope = scope | names
            for condition in generator.ifs:
                self._check(condition, depth + 1, scope)
        self._check(node.elt, depth + 1, scope)

    def _target_names(self, target: ast.AST) -> frozenset[str]:
        if isinstance(target, ast.Name):
            if target.id.startswith("_"):
                self._fail(f"comprehension variable {target.id!r} is not allowed")
            return frozenset({target.id})
        if isinstance(target, (ast.Tuple, ast.List)):
            names: set[str] = set()
            for element in target.elts:
                if isinstance(element, ast.Starred):
                    self._fail("starred comprehension targets are not allowed")
                names |= self._target_names(element)
            return frozenset(names)
        self._fail("comprehension targets must be plain variable names")
        return frozenset()


def evaluate_expression(
    expression: ast.Expression,
    context: Mapping[str, Any],
    *,
    functions: Mapping[str, Any] | None = None,
) -> Any:
    """Evaluate a checked expression against a resource context."""

    if not isinstance(expression, ast.Expression):
        raise EvaluationError("expression must be the result of compile_expression()")
    evaluator = _Evaluator(functions or FUNCTIONS)
    return evaluator.evaluate(expression, context)


class _Evaluator:
    def __init__(self, functions: Mapping[str, Any]) -> None:
        self.functions = functions
        self.steps = 0

    def _step(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise EvaluationError(
                f"evaluation exceeded the maximum of {MAX_STEPS} steps; "
                "narrow the policy or the input"
            )

    def evaluate(self, node: ast.Expression, context: Mapping[str, Any]) -> Any:
        env = dict(context)
        for name in ("resource", "related"):
            env.setdefault(name, {} if name == "resource" else [])
        return self._eval(node.body, env)

    def _eval(self, node: ast.AST, env: dict[str, Any]) -> Any:
        self._step()
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            if node.id in self.functions:
                return self.functions[node.id]
            raise EvaluationError(f"name {node.id!r} is not available")
        if isinstance(node, ast.Attribute):
            return _get_attr(self._eval(node.value, env), node.attr)
        if isinstance(node, ast.Subscript):
            return _get_item(self._eval(node.value, env), self._eval(node.slice, env))
        if isinstance(node, ast.Slice):
            return slice(
                self._eval(node.lower, env) if node.lower is not None else None,
                self._eval(node.upper, env) if node.upper is not None else None,
                self._eval(node.step, env) if node.step is not None else None,
            )
        if isinstance(node, ast.List):
            return [self._eval(element, env) for element in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(self._eval(element, env) for element in node.elts)
        if isinstance(node, ast.Set):
            return {self._eval(element, env) for element in node.elts}
        if isinstance(node, ast.Dict):
            result: dict[Any, Any] = {}
            for key, value in zip(node.keys, node.values, strict=True):
                key_value = self._eval(key, env)
                try:
                    result[key_value] = self._eval(value, env)
                except TypeError as exc:
                    raise EvaluationError("dictionary key is not hashable") from exc
            return result
        if isinstance(node, ast.BinOp):
            return self._binop(node, env)
        if isinstance(node, ast.UnaryOp):
            operand = self._eval(node.operand, env)
            try:
                return _UNARY_OPS[type(node.op)](operand)
            except (TypeError, ValueError) as exc:
                raise EvaluationError(
                    f"cannot apply {type(node.op).__name__} to {type(operand).__name__}"
                ) from exc
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                result: Any = True
                for value_node in node.values:
                    result = self._eval(value_node, env)
                    if not result:
                        return result
                return result
            result = False
            for value_node in node.values:
                result = self._eval(value_node, env)
                if result:
                    return result
            return result
        if isinstance(node, ast.Compare):
            return self._compare(node, env)
        if isinstance(node, ast.IfExp):
            return (
                self._eval(node.body, env)
                if self._eval(node.test, env)
                else self._eval(node.orelse, env)
            )
        if isinstance(node, ast.Call):
            return self._call(node, env)
        if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
            return self._comprehension(node, env)
        raise EvaluationError(f"cannot evaluate {type(node).__name__}")

    def _binop(self, node: ast.BinOp, env: dict[str, Any]) -> Any:
        left = self._eval(node.left, env)
        right = self._eval(node.right, env)
        op = _BIN_OPS[type(node.op)]
        if isinstance(node.op, ast.Mult):
            for sequence, count in ((left, right), (right, left)):
                if (
                    isinstance(sequence, (str, list, tuple))
                    and isinstance(count, int)
                    and len(sequence) * max(count, 0) > _MAX_SEQUENCE
                ):
                    raise EvaluationError("multiplication result is too large")
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)) and right == 0:
            raise EvaluationError("division by zero")
        try:
            return op(left, right)
        except (TypeError, ValueError, OverflowError) as exc:
            raise EvaluationError(
                f"cannot apply {type(node.op).__name__} to "
                f"{type(left).__name__} and {type(right).__name__}"
            ) from exc

    def _compare(self, node: ast.Compare, env: dict[str, Any]) -> bool:
        left = self._eval(node.left, env)
        for op, comparator_node in zip(node.ops, node.comparators, strict=True):
            right = self._eval(comparator_node, env)
            if not _compare_values(op, left, right):
                return False
            left = right
        return True

    def _call(self, node: ast.Call, env: dict[str, Any]) -> Any:
        if not isinstance(node.func, ast.Name) or node.func.id not in self.functions:
            raise EvaluationError("call target is not whitelisted")
        function = self.functions[node.func.id]
        args = []
        for arg in node.args:
            if isinstance(arg, ast.Starred):
                raise EvaluationError("starred arguments are not allowed")
            args.append(self._eval(arg, env))
        kwargs = {}
        for keyword in node.keywords:
            if keyword.arg is None:
                raise EvaluationError("dictionary keyword arguments are not allowed")
            kwargs[keyword.arg] = self._eval(keyword.value, env)
        try:
            return function(*args, **kwargs)
        except ExpressionError:
            raise
        except TypeError as exc:
            raise EvaluationError(
                f"{node.func.id}() received invalid arguments: {_short_error(exc)}"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - policy functions are local and pure
            raise EvaluationError(f"{node.func.id}() failed: {_short_error(exc)}") from exc

    def _comprehension(self, node: ast.ListComp | ast.GeneratorExp, env: dict[str, Any]) -> list:
        results: list[Any] = []

        def run(index: int, scope: dict[str, Any]) -> None:
            if index == len(node.generators):
                results.append(self._eval(node.elt, scope))
                return
            generator = node.generators[index]
            iterable = self._eval(generator.iter, scope)
            for item in _iterate(iterable):
                self._step()
                nested = dict(scope)
                _bind_target(generator.target, item, nested)
                if all(self._eval(condition, nested) for condition in generator.ifs):
                    run(index + 1, nested)

        run(0, dict(env))
        return results


def _iterate(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        return list(value.keys())
    if isinstance(value, (str, bytes)):
        return list(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return []


def _bind_target(target: ast.AST, value: Any, env: dict[str, Any]) -> None:
    if isinstance(target, ast.Name):
        env[target.id] = value
        return
    if isinstance(target, (ast.Tuple, ast.List)):
        values = list(_iterate(value))
        if len(values) != len(target.elts):
            raise EvaluationError("cannot unpack comprehension value")
        for element, item in zip(target.elts, values, strict=True):
            _bind_target(element, item, env)
        return
    raise EvaluationError("invalid comprehension target")


def _compare_values(op: ast.cmpop, left: Any, right: Any) -> bool:
    if isinstance(op, ast.Is):
        return left is right
    if isinstance(op, ast.IsNot):
        return left is not right
    if isinstance(op, (ast.In, ast.NotIn)):
        if right is None:
            return False
        try:
            found = left in right
        except TypeError:
            return False
        return found if isinstance(op, ast.In) else not found
    if isinstance(op, (ast.Eq, ast.NotEq)):
        try:
            equal = left == right
        except Exception:  # noqa: BLE001 - hostile comparison inputs
            return False
        return equal if isinstance(op, ast.Eq) else not equal
    if left is None or right is None:
        return False
    comparator = _COMPARE_OPS.get(type(op))
    if comparator is None:
        return False
    try:
        return bool(comparator(left, right))
    except (TypeError, ValueError):
        return False


def _get_attr(value: Any, name: str) -> Any:
    """Read a mapping key; never touch Python attributes of arbitrary objects."""

    if isinstance(value, Mapping):
        return value.get(name)
    return None


def _get_item(value: Any, key: Any) -> Any:
    if isinstance(value, Mapping):
        try:
            return value.get(key)
        except TypeError:
            return None
    if isinstance(value, (list, tuple, str)):
        if isinstance(key, slice):
            try:
                return value[key]
            except (TypeError, ValueError):
                return None
        if isinstance(key, int):
            try:
                return value[key]
            except IndexError:
                return None
    return None


def _short_error(exc: Exception) -> str:
    text = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
    return text[:200]
