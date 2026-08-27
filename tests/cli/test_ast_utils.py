import textwrap
from datetime import datetime

import libcst as cst
import pytest

from qulf.cli.ast_utils import (
    ModelInjector,
    create_fallback_cst_nodes,
    extract_nodes_from_source,
)


def test_extract_nodes_from_source() -> None:
    source_code = textwrap.dedent("""
    def get_django_columns(self):
        return {
            "user": {
                "test_field": models.CharField(max_length=100)
            },
            "session": {
                "is_active": models.BooleanField(default=True)
            }
        }
    """)
    nodes = extract_nodes_from_source(source_code)

    assert "user" in nodes
    assert "session" in nodes
    assert "test_field" in nodes["user"]
    assert "is_active" in nodes["session"]

    # Verify we extracted the actual CST nodes for the values
    assert isinstance(nodes["user"]["test_field"][0], cst.Call)


def test_create_fallback_cst_nodes() -> None:
    # Django Fallbacks
    dj_str_val, dj_str_ann = create_fallback_cst_nodes("django", str)
    assert (
        "CharField"
        in cst.Module(body=[cst.SimpleStatementLine(body=[cst.Expr(dj_str_val)])]).code
    )
    assert dj_str_ann is None

    dj_bool_val, _ = create_fallback_cst_nodes("django", bool)
    assert (
        "BooleanField"
        in cst.Module(body=[cst.SimpleStatementLine(body=[cst.Expr(dj_bool_val)])]).code
    )

    dj_date_val, _ = create_fallback_cst_nodes("django", datetime)
    assert (
        "DateTimeField"
        in cst.Module(body=[cst.SimpleStatementLine(body=[cst.Expr(dj_date_val)])]).code
    )

    # SQLAlchemy Fallbacks (Needs Annotations)
    sa_str_val, sa_str_ann = create_fallback_cst_nodes("sqlalchemy", str)
    assert (
        "mapped_column(String"
        in cst.Module(body=[cst.SimpleStatementLine(body=[cst.Expr(sa_str_val)])]).code
    )
    assert (
        "Mapped[str | None]"
        in cst.Module(body=[cst.SimpleStatementLine(body=[cst.Expr(sa_str_ann)])]).code
    )

    sa_bool_val, sa_bool_ann = create_fallback_cst_nodes("sqlalchemy", bool)
    assert (
        "mapped_column(Boolean"
        in cst.Module(body=[cst.SimpleStatementLine(body=[cst.Expr(sa_bool_val)])]).code
    )

    sa_date_val, sa_date_ann = create_fallback_cst_nodes("sqlalchemy", datetime)
    assert (
        "mapped_column(DateTime"
        in cst.Module(body=[cst.SimpleStatementLine(body=[cst.Expr(sa_date_val)])]).code
    )

    # SQLModel Fallbacks
    sm_str_val, sm_str_ann = create_fallback_cst_nodes("sqlmodel", str)
    assert (
        "Field"
        in cst.Module(body=[cst.SimpleStatementLine(body=[cst.Expr(sm_str_val)])]).code
    )
    assert (
        "str | None"
        in cst.Module(body=[cst.SimpleStatementLine(body=[cst.Expr(sm_str_ann)])]).code
    )

    sm_bool_val, sm_bool_ann = create_fallback_cst_nodes("sqlmodel", bool)
    assert (
        "Field"
        in cst.Module(body=[cst.SimpleStatementLine(body=[cst.Expr(sm_bool_val)])]).code
    )

    sm_date_val, sm_date_ann = create_fallback_cst_nodes("sqlmodel", datetime)
    assert (
        "Field"
        in cst.Module(body=[cst.SimpleStatementLine(body=[cst.Expr(sm_date_val)])]).code
    )

    # Unsupported Fallback
    with pytest.raises(ValueError, match="Unsupported fallback type"):
        create_fallback_cst_nodes("django", float)

    with pytest.raises(ValueError, match="Unsupported fallback type"):
        create_fallback_cst_nodes("unknown_orm", str)


def test_model_injector_injection_and_grouping() -> None:
    # Use textwrap to ensure valid formatting
    original_code = textwrap.dedent("""
    class User:
        id = 1
        existing_field = "test"
        existing_ann: str = "ann"
        
        class Meta:
            db_table = "users"
            
    class UntouchedClass:
        pass
    """)
    tree = cst.parse_module(original_code)

    # Mock CST Nodes for injection
    val1 = cst.parse_expression("models.CharField()")
    val2 = cst.parse_expression("models.BooleanField()")
    ann1 = cst.parse_expression("Mapped[str]")

    injections = {
        "User": {
            "existing_field": (val1, None, "plugin_a"),  # Should be skipped (Assign)
            "existing_ann": (val1, None, "plugin_a"),  # Should be skipped (AnnAssign)
            "new_field_1": (val1, ann1, "plugin_a"),  # Uses AnnAssign
            "new_field_2": (val2, None, "plugin_a"),  # Uses standard Assign
            "new_field_3": (val1, None, "plugin_b"),  # Triggers NEW header comment
        },
        "UnknownClass": {
            "ignored": (val1, None, "plugin_a")  # Should be ignored entirely
        },
    }

    injector = ModelInjector(injections)
    modified_tree = tree.visit(injector)
    modified_code = modified_tree.code

    # 1. Check skips
    assert len(injector.skipped_fields) == 2
    assert ("User", "existing_field") in injector.skipped_fields
    assert ("User", "existing_ann") in injector.skipped_fields

    # 2. Check injections
    assert len(injector.injected_fields) == 3
    assert "new_field_1: Mapped[str] = models.CharField()" in modified_code
    assert "new_field_2 = models.BooleanField()" in modified_code

    # 3. Check grouping comments
    assert modified_code.count("# Injected by plugin_a") == 1
    assert modified_code.count("# Injected by plugin_b") == 1
