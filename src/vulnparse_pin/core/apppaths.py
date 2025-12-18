from importlib import resources
import os
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from vulnparse_pin import __version__

try:
    from platformdirs import user_config_dir, user_data_dir, user_cache_dir, user_log_dir
except ImportError as e:
    raise RuntimeError(
        "Missing dependency: platformdirs. Install with pip install platformdirs"
    ) from e

APP_NAME = "VulnParse-Pin"
APP_AUTHOR = "Shade216"

def _truthy_env(name: str) -> bool:
    v = os.getenv(name, "").strip().lower()
    return v in {"1", "true", "yes", "y", "on"}

def _portable_base() -> Path:
    """
    Decide where portable 'data/' lives.
    - If frozen (Pyinstaller), use directory of executable.
    - Else use current working directory or script dir.
    """
    # PyInstaller
    if getattr(os, "frozen", False):
        import sys
        return Path(sys.executable).resolve().parent
    
    # Run from source/venv/etc
    return Path.cwd().resolve()

@dataclass
class AppPaths:
    portable: bool
    base_dir: Path          # OS-native base or portable base
    config_dir: Path
    data_dir: Path
    cache_dir: Path
    log_dir: Path
    output_dir: Path

    @classmethod
    def resolve(cls, *, portable: bool | None = None) -> "AppPaths":
        if portable is None:
            portable = _truthy_env("VULNPARSE_PIN_PORTABLE")
        
        if portable:
            base = _portable_base()
            data_root = base / "data"
            config_dir = base / "config"
            data_dir = data_root
            cache_dir = data_root / "caches"
            log_dir = data_root / "logs"
            output_dir = data_root / "output"
        else:
            config_dir = Path(user_config_dir(APP_NAME, APP_AUTHOR, __version__))
            data_dir = Path(user_data_dir(APP_NAME, APP_AUTHOR, __version__))
            cache_dir = Path(user_cache_dir(APP_NAME, APP_AUTHOR, __version__))
            log_dir = Path(user_log_dir(APP_NAME, APP_AUTHOR, __version__))
            output_dir = data_dir / "output"
            base = data_dir

        return cls(
            portable = portable,
            base_dir = base,
            config_dir = config_dir,
            data_dir = data_dir,
            cache_dir = cache_dir,
            log_dir = log_dir,
            output_dir = output_dir,
        )

    def ensure_dirs(self) -> None:
        """
        Create req'd application directories and apply best-effort permission hardening.
        """
        dirs = {
            self.config_dir: 0o700,     # Sensitive - Keep this to power users.
            self.cache_dir: 0o700,      # Sensitive - No one really needs to dig in here other than the owner(power user).
            self.log_dir: 0o700,        # Senstive, but Users of same group can read(e.g., Sysadmins).
            self.output_dir: 0o750,     # Self explainable
        }

        for path, mode in dirs.items():
            path.mkdir(parents=True, exist_ok=True)
            _harden_dir(path, mode)

    def config_path_yaml(self) -> Path:
        return self.config_dir / "config.yaml"

    def config_path_json(self) -> Path:
        return self.config_dir / "scoring.json"

def ensure_user_configs(paths: AppPaths) -> Tuple[Path, Path]:
    """
    Ensure config.yaml and/or scoring.json exists in the writable config dir.
    If missing, copy from package resource default.
    """
    paths.ensure_dirs()
    dst_yaml = paths.config_path_yaml() # e.g., .../config/config.yaml
    dst_json = paths.config_path_json() # e.g., .../config/scoring.json

    #   Create missing Global config YAML
    if not dst_yaml.exists():
        default_bytes_yaml = resources.files("vulnparse_pin.resources").joinpath("config.yaml").read_bytes()
        dst_yaml.write_bytes(default_bytes_yaml)
        return dst_yaml
    #   Create missing Scoring config JSON
    if not dst_json.exists():
        default_bytes_json = resources.files("vulnparse_pin.resources").joinpath("scoring.json").read_bytes()
        dst_json.write_bytes(default_bytes_json)
        return dst_json
    
    return dst_yaml, dst_json

def load_config(paths: AppPaths) -> Tuple[dict, dict]:
    """
    Loads config files for VulnParse-Pin.
    - Global Config: config.yaml
    - Scoring Config: scoring.json
    
    :param paths: Various attributes available from AppPaths dataclass.
    :type paths: AppPaths
    :return: Returns dict objects with config data.
    :rtype: Tuple[dict, dict]
    """
    cfg_path_yaml, cfg_path_json = ensure_user_configs(paths)

    # YAML INIT
    yaml=YAML(typ = "safe", pure = True)
    try:
        cfg_yaml = yaml.load(cfg_path_yaml.read_text(encoding="utf-8"))
    except (TypeError, ValueError, YAMLError) as e:
        raise RuntimeError("Could not parse yaml file.") from e
    
    try:
        cfg_json = json.loads(cfg_path_json.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        raise RuntimeError("Could not load json config file.") from e

    if not isinstance(cfg_json, dict):
        raise RuntimeError("Scoring config must be an object at top-level.")
    
    return cfg_yaml, cfg_json

def _harden_dir(path: Path, mode: int) -> None:
    """
    Best effort POSIX perm hardening.
    No-op on windows.
    """
    if os.name == "nt":
        return

    try:
        current = stat.S_IMODE(path.stat().st_mode)
        if current != mode:
            path.chmod(mode)
    except Exception as e:
        raise PermissionError("Invalid permissions. Unable to set permission mode on path.") from e