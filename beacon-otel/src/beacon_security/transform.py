from __future__ import annotations

import ast
import os
import symtable
from collections import deque

FRAME_SENSITIVE = {
    "super",
    "locals",
    "globals",
    "vars",
    "dir",
    "eval",
    "exec",
    "compile",
    "__build_class__",
    "_getframe",
    "currentframe",
}
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_AST_NODES = 50000
MAX_ANALYSIS_WORK = 100000


class TransformLimit(Exception):
    pass


def frame_sensitive_aliases(tree):
    names = set(FRAME_SENSITIVE)
    dependents = {}
    remaining = MAX_ANALYSIS_WORK

    def spend():
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            raise TransformLimit("transform_analysis_limit")

    for node in ast.walk(tree):
        spend()
        if isinstance(node, ast.ImportFrom) and node.module in {
            "builtins",
            "sys",
            "inspect",
        }:
            names.update(
                item.asname or item.name
                for item in node.names
                if item.name in FRAME_SENSITIVE
            )
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
            for target in targets:
                spend()
                if not isinstance(target, ast.Name):
                    continue
                if isinstance(node.value, ast.Name):
                    dependents.setdefault(node.value.id, set()).add(target.id)
                elif (
                    isinstance(node.value, ast.Attribute)
                    and node.value.attr in FRAME_SENSITIVE
                ):
                    names.add(target.id)
    # A shadowed name may reduce coverage, but must never change the frame in
    # which a built-in (or a later reassignment of its alias) executes.
    pending = deque(names)
    while pending:
        for target in dependents.get(pending.popleft(), ()):
            spend()
            if target not in names:
                names.add(target)
                pending.append(target)
    return names


class Transformer(ast.NodeTransformer):
    def __init__(self, module, filename, alias, sensitive_names):
        self.module = module
        self.filename = os.path.basename(filename)
        self.alias = alias
        self.functions = []
        self.classes = []
        self.sensitive_names = sensitive_names

    def location(self, node):
        name = ".".join(self.classes + self.functions) or "<module>"
        return ast.Constant(
            f"{self.module}#{name}({self.filename}:{getattr(node, 'lineno', 0)})"
        )

    def helper(self, name, args, node, keywords=None):
        return ast.copy_location(
            ast.Call(
                ast.Attribute(
                    ast.Name(self.alias, ast.Load()), name, ast.Load()
                ),
                args,
                keywords or [],
            ),
            node,
        )

    def visit_ClassDef(self, node):
        self.classes.append(node.name)
        node.body = [self.visit(item) for item in node.body]
        self.classes.pop()
        return node

    def visit_FunctionDef(self, node):
        self.functions.append(node.name)
        node.body = [self.visit(item) for item in node.body]
        self.functions.pop()
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        self.functions.append("<lambda>")
        node.body = self.visit(node.body)
        self.functions.pop()
        return node

    def visit_AnnAssign(self, node):
        if node.value is not None:
            node.value = self.visit(node.value)
        node.target = self.visit(node.target)
        return node

    def visit_BinOp(self, node):
        if not self.functions:
            return node
        node = self.generic_visit(node)
        operation = type(node.op).__name__
        if operation in ("Add", "Mod", "Div"):
            return self.helper(
                "binary",
                [
                    node.left,
                    node.right,
                    ast.Constant(operation),
                    self.location(node),
                ],
                node,
            )
        return node

    def visit_AugAssign(self, node):
        if (
            self.functions
            and isinstance(node.op, ast.Add)
            and isinstance(node.target, ast.Name)
        ):
            target = ast.copy_location(
                ast.Name(node.target.id, ast.Load()), node.target
            )
            # A generator can resume under a different Context; a context token
            # must not span yield/yield-from. Keep the native operation and flag
            # the propagation boundary instead of adding a caller-owned token.
            if any(
                isinstance(item, (ast.Yield, ast.YieldFrom))
                for item in ast.walk(node.value)
            ):
                value = self.helper(
                    "unmodeled",
                    [
                        self.visit(node.value),
                        ast.Constant("generator_iadd_propagation"),
                    ],
                    node,
                )
                return ast.copy_location(
                    ast.AugAssign(node.target, node.op, value), node
                )
            operand = self.helper(
                "iadd_operand", [target, self.visit(node.value)], node
            )
            operation = ast.copy_location(
                ast.AugAssign(node.target, node.op, operand), node
            )
            after = ast.Expr(
                self.helper("iadd_result", [target, self.location(node)], node)
            )
            # Keep the native opcode and no extra reference to its left operand:
            # CPython can then reuse an unaliased string's buffer. The context
            # handles nested operations and exceptions without business locals.
            return ast.copy_location(
                ast.With(
                    [ast.withitem(self.helper("AugmentedAdd", [], node))],
                    [operation, after],
                ),
                node,
            )
        return self.generic_visit(node)

    def _key(self, node):
        if isinstance(node, ast.Slice):
            return self.helper(
                "make_slice",
                [
                    self.visit(value)
                    if value is not None
                    else ast.Constant(None)
                    for value in (node.lower, node.upper, node.step)
                ],
                node,
            )
        if isinstance(node, ast.Tuple):
            return ast.copy_location(
                ast.Tuple(
                    [self._key(value) for value in node.elts], ast.Load()
                ),
                node,
            )
        return self.visit(node)

    def visit_Subscript(self, node):
        if not self.functions or not isinstance(node.ctx, ast.Load):
            return self.generic_visit(node)
        return self.helper(
            "subscript",
            [
                self.visit(node.value),
                self._key(node.slice),
                self.location(node),
            ],
            node,
        )

    def visit_Attribute(self, node):
        if not self.functions or not isinstance(node.ctx, ast.Load):
            return self.generic_visit(node)
        name = node.attr
        if self.classes and name.startswith("__") and not name.endswith("__"):
            class_name = self.classes[-1].lstrip("_")
            if class_name:
                name = "_" + class_name + name
        return self.helper(
            "attribute",
            [self.visit(node.value), ast.Constant(name), self.location(node)],
            node,
        )

    def sensitive(self, node):
        if isinstance(node.func, ast.Name):
            return node.func.id in self.sensitive_names
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in FRAME_SENSITIVE
        )

    def _call(self, node, helper="call"):
        function = self.visit(node.func)
        args = [self.visit(arg) for arg in node.args]
        keywords = [
            ast.keyword(arg=kw.arg, value=self.visit(kw.value))
            for kw in node.keywords
        ]
        target = self.helper(
            "call_target",
            [function, self.location(node), ast.Constant(helper == "acall")],
            node,
        )
        return ast.copy_location(ast.Call(target, args, keywords), node)

    def visit_Call(self, node):
        if not self.functions:
            return self.generic_visit(node)
        if self.sensitive(node):
            node = self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id in {
                "eval",
                "exec",
            }:
                return self.helper(
                    "unmodeled",
                    [node, ast.Constant("dynamic_code_execution")],
                    node,
                )
            return node
        return self._call(node)

    def visit_Await(self, node):
        if (
            self.functions
            and isinstance(node.value, ast.Call)
            and not self.sensitive(node.value)
        ):
            return ast.copy_location(
                ast.Await(self._call(node.value, "acall")), node
            )
        return self.generic_visit(node)

    def visit_JoinedStr(self, node):
        if not self.functions:
            return node
        pieces = []
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                spec = (
                    self.visit(part.format_spec)
                    if part.format_spec is not None
                    else ast.Constant("")
                )
                pieces.append(
                    self.helper(
                        "formatted",
                        [
                            self.visit(part.value),
                            ast.Constant(part.conversion),
                            spec,
                            self.location(part),
                        ],
                        part,
                    )
                )
            else:
                pieces.append(part)
        return self.helper(
            "joined",
            [ast.Tuple(pieces, ast.Load()), self.location(node)],
            node,
        )


def transform(source, filename, module):
    if (
        len(source) > MAX_SOURCE_BYTES
        or len(source.encode("utf-8") if isinstance(source, str) else source)
        > MAX_SOURCE_BYTES
    ):
        raise TransformLimit("transform_source_limit")
    tree = ast.parse(source, filename=filename)
    for count, _ in enumerate(ast.walk(tree), 1):
        if count > MAX_AST_NODES:
            raise TransformLimit("transform_node_limit")
    tables = [symtable.symtable(source, filename, "exec")]
    names = set()
    while tables:
        table = tables.pop()
        names.update(table.get_identifiers())
        tables.extend(table.get_children())
    alias = "__beacon_security_hooks__"
    while alias in names:
        alias = alias[:-2] + "_x__"
    tree = Transformer(
        module, filename, alias, frame_sensitive_aliases(tree)
    ).visit(tree)
    import_node = ast.Import(
        names=[ast.alias(name="beacon_security.ast_hooks", asname=alias)]
    )
    index = (
        1
        if tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
        else 0
    )
    while (
        index < len(tree.body)
        and isinstance(tree.body[index], ast.ImportFrom)
        and tree.body[index].module == "__future__"
    ):
        index += 1
    tree.body.insert(index, import_node)
    return ast.fix_missing_locations(tree)
