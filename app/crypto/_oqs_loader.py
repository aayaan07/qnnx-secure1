import os
from pathlib import Path


def _shared_library_candidates(base_dir: Path):
    return (
        base_dir / "bin" / "oqs.dll",
        base_dir / "bin" / "liboqs.dll",
        base_dir / "bin" / "Debug" / "oqs.dll",
        base_dir / "bin" / "Debug" / "liboqs.dll",
        base_dir / "bin" / "Release" / "oqs.dll",
        base_dir / "bin" / "Release" / "liboqs.dll",
        base_dir / "lib" / "liboqs.so",
        base_dir / "lib64" / "liboqs.so",
        base_dir / "lib" / "liboqs.dylib",
    )


def _has_shared_library(base_dir: Path) -> bool:
    return any(path.exists() for path in _shared_library_candidates(base_dir))


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _resolve_oqs_root(path_value: str | Path | None) -> Path | None:
    if not path_value:
        return None

    base_dir = Path(path_value)

    if base_dir.is_file() and base_dir.name.lower() in {"oqs.dll", "liboqs.dll"}:
        if base_dir.parent.name.lower() in {"debug", "release"}:
            return base_dir.parents[2]
        return base_dir.parent.parent

    if _has_shared_library(base_dir):
        return base_dir

    for parent in (base_dir, *base_dir.parents):
        if _has_shared_library(parent):
            return parent

    return None


def _candidate_install_paths():
    repo_root = _repo_root()
    return [
        repo_root / ".oqs",
        repo_root / "libs" / "liboqs" / "build",
        repo_root / "libs" / "liboqs" / "install",
        repo_root / "liboqs" / "build",
        repo_root / "liboqs" / "install",
        repo_root / "liboqs-local",
    ]


def _configure_oqs_install_path():
    env_root = _resolve_oqs_root(os.environ.get("OQS_INSTALL_PATH"))
    if env_root:
        os.environ["OQS_INSTALL_PATH"] = str(env_root)
        return

    for candidate in _candidate_install_paths():
        resolved = _resolve_oqs_root(candidate)
        if resolved:
            os.environ["OQS_INSTALL_PATH"] = str(resolved)
            return


def _require_liboqs():
    env_root = _resolve_oqs_root(os.environ.get("OQS_INSTALL_PATH"))
    if env_root:
        os.environ["OQS_INSTALL_PATH"] = str(env_root)
        return

    for candidate in _candidate_install_paths():
        resolved = _resolve_oqs_root(candidate)
        if resolved:
            os.environ["OQS_INSTALL_PATH"] = str(resolved)
            return

    raise RuntimeError(
        "liboqs is not available. Install or build liboqs, then set "
        "OQS_INSTALL_PATH to its install directory, or place it in '.oqs', "
        "'libs/liboqs', or 'liboqs' in the repo root."
    )


def load_key_encapsulation():
    _configure_oqs_install_path()
    _require_liboqs()
    try:
        from oqs import KeyEncapsulation
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "liboqs was found, but the Python 'oqs' package is not installed in the current interpreter. "
            "Use the project virtualenv or install liboqs-python in this Python environment."
        ) from exc
    except Exception as exc:
        raise RuntimeError("Failed to import liboqs-python even though liboqs was found.") from exc
    return KeyEncapsulation


def load_signature():
    _configure_oqs_install_path()
    _require_liboqs()
    try:
        from oqs import Signature
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "liboqs was found, but the Python 'oqs' package is not installed in the current interpreter. "
            "Use the project virtualenv or install liboqs-python in this Python environment."
        ) from exc
    except Exception as exc:
        raise RuntimeError("Failed to import liboqs-python even though liboqs was found.") from exc
    return Signature