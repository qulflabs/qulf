import libcst as cst


class PluginDictExtractor(cst.CSTVisitor):
    """Visits a plugin method's AST to extract the returned dictionary node."""

    def __init__(self) -> None:
        # Maps table_name -> {col_name: (value_node, annotation_node_or_none)}
        self.extracted_nodes: dict[
            str, dict[str, tuple[cst.BaseExpression, cst.BaseExpression | None]]
        ] = {}

    def visit_Return(self, node: cst.Return) -> None:
        if isinstance(node.value, cst.Dict):
            for element in node.value.elements:
                if isinstance(element, cst.DictElement) and isinstance(
                    element.key, cst.SimpleString
                ):
                    table_name = element.key.value.strip("'\"")
                    self.extracted_nodes[table_name] = {}

                    if isinstance(element.value, cst.Dict):
                        for col_element in element.value.elements:
                            if isinstance(col_element, cst.DictElement) and isinstance(
                                col_element.key, cst.SimpleString
                            ):
                                col_name = col_element.key.value.strip("'\"")
                                self.extracted_nodes[table_name][col_name] = (
                                    col_element.value,
                                    None,
                                )


class ModelInjector(cst.CSTTransformer):
    """Safely injects CSTNodes into target classes in the user's models.py."""

    def __init__(
        self,
        injections: dict[
            str,
            dict[
                str,
                tuple[
                    cst.BaseExpression,
                    cst.BaseExpression | None,
                    str,
                ],
            ],
        ],
    ) -> None:
        self.injections = injections
        self.injected_fields: list[tuple[str, str]] = []
        self.skipped_fields: list[tuple[str, str]] = []

    def leave_ClassDef(
        self, original_node: cst.ClassDef, updated_node: cst.ClassDef
    ) -> cst.ClassDef:
        class_name = original_node.name.value
        if class_name not in self.injections:
            return updated_node

        existing_fields = set()
        for statement in original_node.body.body:
            if isinstance(statement, cst.SimpleStatementLine):
                for elem in statement.body:
                    if isinstance(elem, cst.Assign):
                        for target in elem.targets:
                            if isinstance(target.target, cst.Name):
                                existing_fields.add(target.target.value)
                    elif isinstance(elem, cst.AnnAssign):
                        if isinstance(elem.target, cst.Name):
                            existing_fields.add(elem.target.value)

        new_statements = list(updated_node.body.body)
        cols_to_inject = self.injections[class_name]

        insert_idx = len(new_statements)
        for i, stmt in enumerate(new_statements):
            if isinstance(stmt, (cst.ClassDef, cst.FunctionDef)):
                insert_idx = i
                break

        injected_stmts = []
        from datetime import datetime

        today_str = datetime.now().strftime("%Y-%m-%d")

        last_plugin_name: str | None = None

        for col_name, (col_node, ann_node, plugin_name) in cols_to_inject.items():
            if col_name in existing_fields:
                self.skipped_fields.append((class_name, col_name))
                continue

            assign: cst.BaseSmallStatement

            if ann_node:
                assign = cst.AnnAssign(
                    target=cst.Name(col_name),
                    annotation=cst.Annotation(ann_node),
                    value=col_node,
                )
            else:
                assign = cst.Assign(
                    targets=[cst.AssignTarget(cst.Name(col_name))],
                    value=col_node,
                )

            if plugin_name != last_plugin_name:
                comment_line = cst.EmptyLine(
                    comment=cst.Comment(f"# Injected by {plugin_name}: {today_str}")
                )
                stmt = cst.SimpleStatementLine(
                    leading_lines=[comment_line], body=[assign]
                )
                last_plugin_name = plugin_name
            else:
                stmt = cst.SimpleStatementLine(body=[assign])

            injected_stmts.append(stmt)
            self.injected_fields.append((class_name, col_name))

        new_statements[insert_idx:insert_idx] = injected_stmts
        new_body = updated_node.body.with_changes(body=new_statements)
        return updated_node.with_changes(body=new_body)


def extract_nodes_from_source(
    source_code: str,
) -> dict[str, dict[str, tuple[cst.BaseExpression, cst.BaseExpression | None]]]:
    """Takes a plugin method's source code and extracts the returned dictionary."""
    tree = cst.parse_module(source_code)
    extractor = PluginDictExtractor()
    tree.visit(extractor)
    return extractor.extracted_nodes


def create_fallback_cst_nodes(
    orm_name: str, col_type: type
) -> tuple[cst.BaseExpression, cst.BaseExpression | None]:
    """Creates (ValueNode, AnnotationNode) for generic python types."""
    from datetime import datetime

    if orm_name == "django":
        if col_type is str:
            return cst.parse_expression(
                "models.CharField(max_length=255, null=True, blank=True)"
            ), None
        elif col_type is bool:
            return cst.parse_expression("models.BooleanField(default=False)"), None
        elif col_type is datetime:
            return cst.parse_expression(
                "models.DateTimeField(null=True, blank=True)"
            ), None

    elif orm_name == "sqlalchemy":
        if col_type is str:
            return cst.parse_expression(
                "mapped_column(String, nullable=True)"
            ), cst.parse_expression("Mapped[str | None]")
        elif col_type is bool:
            return cst.parse_expression(
                "mapped_column(Boolean, default=False)"
            ), cst.parse_expression("Mapped[bool]")
        elif col_type is datetime:
            return cst.parse_expression(
                "mapped_column(DateTime(timezone=True), nullable=True)"
            ), cst.parse_expression("Mapped[datetime | None]")

    elif orm_name == "sqlmodel":
        if col_type is str:
            return cst.parse_expression(
                "Field(default=None, nullable=True)"
            ), cst.parse_expression("str | None")
        elif col_type is bool:
            return cst.parse_expression("Field(default=False)"), cst.parse_expression(
                "bool"
            )
        elif col_type is datetime:
            return cst.parse_expression(
                "Field(default=None, nullable=True)"
            ), cst.parse_expression("datetime | None")

    raise ValueError(f"Unsupported fallback type {col_type!r} for ORM {orm_name!r}")
