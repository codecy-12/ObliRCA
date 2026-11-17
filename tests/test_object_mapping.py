from pathlib import Path

from obli_rca.models.code import CodeFramework, FunctionSlice
from obli_rca.models.obligation import ObligationEntry
from obli_rca.online.object_mapping import BindingState, ObjectMapper

ROOT = Path(__file__).resolve().parents[1]


def test_object_mapper_binds_roles():
    entry = ObligationEntry.load(ROOT / "obligations" / "05_memory_bounds.yaml")
    framework = CodeFramework("test")
    framework.add_slice(
        FunctionSlice(
            application="demo",
            source_version="1.0",
            file="demo.c",
            function="copy",
            start_line=1,
            end_line=10,
            statements=[
                "void copy(char *buffer, int length, int offset) {",
                "  if (length > 0) {",
                "    memcpy(buffer, source, length);",
                "  }",
                "}",
            ],
        )
    )
    mapping = ObjectMapper(entry).bind(framework)
    assert mapping.bindings
    assert any(b.state == BindingState.BOUND for b in mapping.bindings.values())
