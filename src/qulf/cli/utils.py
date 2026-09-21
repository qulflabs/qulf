from importlib.resources import files

from qulf.types import SupportedORM


def load_model_template(orm: SupportedORM) -> str:
    return (files("qulf") / "cli" / "templates" / f"{orm.value}.py").read_text()