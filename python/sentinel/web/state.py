"""Shared application state for the Sentinel dashboard."""

import secrets
import time

from sentinel.web.auth_store import UserStore

# ── Security Constants ───────────────────────────────────────────

MAX_PROMPT_LENGTH = 50_000          # 50KB max prompt
MAX_UPLOAD_SIZE = 500 * 1024 * 1024 # 500MB max upload
MAX_HISTORY_SIZE = 10_000           # max entries in memory
RATE_LIMIT_RPS = 30                 # requests per second per IP
RATE_LIMIT_BURST = 60               # burst capacity
TOKEN_TTL = 8 * 3600               # 8 hours
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW = 60                   # seconds

ALLOWED_UPLOAD_EXTENSIONS = {
    ".pkl", ".pickle", ".p", ".dill",
    ".pt", ".pth", ".bin", ".ckpt",
    ".safetensors", ".gguf", ".pb",
    ".onnx", ".keras", ".h5", ".hdf5",
    ".tflite", ".llamafile",
    ".xgb", ".ubj", ".model", ".lgb",
    ".joblib", ".npy", ".npz",
    ".nemo", ".mar", ".tar", ".tgz", ".zip",
    ".torchscript", ".ptc", ".ptl",
}


class AppState:
    """Mutable shared state for the dashboard, passed to all routers."""

    __slots__ = (
        "engine", "input_pipe", "output_pipe",
        "scan_history", "artifact_history",
        "start_time", "instance_id",
        "valid_tokens", "login_attempts",
        "user_store",
    )

    def __init__(self, engine, input_pipe, output_pipe):
        self.engine = engine
        self.input_pipe = input_pipe
        self.output_pipe = output_pipe
        self.scan_history: list[dict] = []
        self.artifact_history: list[dict] = []
        self.start_time: float = time.time()
        self.instance_id: str = secrets.token_hex(8)
        # token -> (user_id, expiry_timestamp)
        self.valid_tokens: dict[str, tuple[str, float]] = {}
        self.login_attempts: dict[str, list[float]] = {}  # ip -> [timestamps]
        self.user_store: UserStore = UserStore()

    def trim_history(self):
        """Prevent unbounded memory growth."""
        while len(self.scan_history) > MAX_HISTORY_SIZE:
            self.scan_history.pop(0)
        while len(self.artifact_history) > MAX_HISTORY_SIZE:
            self.artifact_history.pop(0)
