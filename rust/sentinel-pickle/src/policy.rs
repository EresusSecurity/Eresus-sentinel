// policy.rs — Allowlist/blocklist policy evaluation for pickle scanning
// Determines whether a given global import (module.name) is safe, dangerous,
// or suspicious based on configurable allowlist and blocklist rules.

use pyo3::prelude::*;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    Safe,
    Dangerous,
    Suspicious,
    Unknown,
}

impl std::fmt::Display for PolicyVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyVerdict::Safe => write!(f, "SAFE"),
            PolicyVerdict::Dangerous => write!(f, "DANGEROUS"),
            PolicyVerdict::Suspicious => write!(f, "SUSPICIOUS"),
            PolicyVerdict::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

static ALWAYS_DANGEROUS: &[(&str, &str)] = &[
    ("os", "system"),
    ("os", "popen"),
    ("os", "exec"),
    ("os", "execl"),
    ("os", "execle"),
    ("os", "execlp"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "execvpe"),
    ("os", "spawn"),
    ("os", "spawnl"),
    ("os", "spawnle"),
    ("posix", "system"),
    ("posix", "popen"),
    ("posix", "exec"),
    ("posix", "execl"),
    ("posix", "execle"),
    ("posix", "execv"),
    ("posix", "execve"),
    ("posix", "spawn"),
    ("posix", "spawnl"),
    ("posix", "spawnle"),
    ("posixpath", "join"),
    ("nt", "system"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "Popen"),
    ("subprocess", "run"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "compile"),
    ("builtins", "__import__"),
    ("builtins", "globals"),
    ("builtins", "getattr"),
    ("builtins", "setattr"),
    ("builtins", "delattr"),
    ("webbrowser", "open"),
    ("socket", "socket"),
    ("ctypes", "CDLL"),
    ("ctypes", "cdll"),
    ("ctypes", "windll"),
    ("ctypes", "oledll"),
    ("ctypes", "pydll"),
    ("shutil", "rmtree"),
    ("shutil", "move"),
    ("importlib", "import_module"),
    ("importlib", "__import__"),
    ("code", "interact"),
    ("code", "compile_command"),
    ("codeop", "compile_command"),
    ("marshal", "loads"),
    ("marshal", "load"),
    ("pickle", "loads"),
    ("pickle", "load"),
    ("_pickle", "loads"),
    ("_pickle", "load"),
    ("shelve", "open"),
    ("tempfile", "mktemp"),
    ("commands", "getoutput"),
    ("commands", "getstatusoutput"),
    ("pdb", "set_trace"),
    ("pty", "spawn"),
    ("http.server", "HTTPServer"),
    ("xmlrpc.server", "SimpleXMLRPCServer"),
];

static SAFE_MODULES: &[&str] = &[
    "collections",
    "datetime",
    "decimal",
    "fractions",
    "functools",
    "itertools",
    "math",
    "operator",
    "pathlib",
    "re",
    "string",
    "typing",
    "enum",
    "dataclasses",
    "copy",
    "copyreg",
    "_codecs",
    "codecs",
];

static ML_SAFE_PREFIXES: &[&str] = &[
    "numpy",
    "torch",
    "tensorflow",
    "sklearn",
    "scipy",
    "pandas",
    "xgboost",
    "lightgbm",
    "catboost",
    "transformers",
    "safetensors",
    "tokenizers",
    "accelerate",
    "diffusers",
    "huggingface_hub",
    "sentencepiece",
    "jax",
    "flax",
    "optax",
    "keras",
];

#[pyclass]
#[derive(Debug, Clone)]
pub struct ScanPolicy {
    allowlist: HashSet<(String, String)>,
    blocklist: HashSet<(String, String)>,
    allowed_modules: HashSet<String>,
    blocked_modules: HashSet<String>,
    strict_mode: bool,
}

#[pymethods]
impl ScanPolicy {
    #[new]
    #[pyo3(signature = (strict_mode=false))]
    pub fn new(strict_mode: bool) -> Self {
        let mut blocklist = HashSet::new();
        for &(module, name) in ALWAYS_DANGEROUS {
            blocklist.insert((module.to_string(), name.to_string()));
        }

        let mut allowed_modules = HashSet::new();
        for &m in SAFE_MODULES {
            allowed_modules.insert(m.to_string());
        }
        if !strict_mode {
            for &prefix in ML_SAFE_PREFIXES {
                allowed_modules.insert(prefix.to_string());
            }
        }

        Self {
            allowlist: HashSet::new(),
            blocklist,
            allowed_modules,
            blocked_modules: HashSet::new(),
            strict_mode,
        }
    }

    pub fn allow(&mut self, module: &str, name: &str) {
        self.allowlist.insert((module.to_string(), name.to_string()));
    }

    pub fn block(&mut self, module: &str, name: &str) {
        self.blocklist.insert((module.to_string(), name.to_string()));
    }

    pub fn allow_module(&mut self, module: &str) {
        self.allowed_modules.insert(module.to_string());
    }

    pub fn block_module(&mut self, module: &str) {
        self.blocked_modules.insert(module.to_string());
    }

    pub fn evaluate(&self, module: &str, name: &str) -> String {
        self.evaluate_internal(module, name).to_string()
    }
}

impl ScanPolicy {
    pub fn evaluate_internal(&self, module: &str, name: &str) -> PolicyVerdict {
        let key = (module.to_string(), name.to_string());

        if self.allowlist.contains(&key) {
            return PolicyVerdict::Safe;
        }
        if self.blocklist.contains(&key) {
            return PolicyVerdict::Dangerous;
        }
        if self.blocked_modules.contains(module) {
            return PolicyVerdict::Dangerous;
        }

        let top_module = module.split('.').next().unwrap_or(module);

        if self.blocked_modules.contains(top_module) {
            return PolicyVerdict::Dangerous;
        }
        if self.allowed_modules.contains(module) || self.allowed_modules.contains(top_module) {
            return PolicyVerdict::Safe;
        }

        if name.starts_with('_') && name != "__reduce__" && name != "__reduce_ex__" {
            return PolicyVerdict::Suspicious;
        }

        if self.strict_mode {
            PolicyVerdict::Suspicious
        } else {
            PolicyVerdict::Unknown
        }
    }

    pub fn default_policy() -> Self {
        Self::new(false)
    }

    pub fn strict_policy() -> Self {
        Self::new(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_builtins() {
        let policy = ScanPolicy::default_policy();
        assert_eq!(policy.evaluate_internal("os", "system"), PolicyVerdict::Dangerous);
        assert_eq!(policy.evaluate_internal("posix", "system"), PolicyVerdict::Dangerous);
        assert_eq!(policy.evaluate_internal("subprocess", "Popen"), PolicyVerdict::Dangerous);
        assert_eq!(policy.evaluate_internal("builtins", "eval"), PolicyVerdict::Dangerous);
    }

    #[test]
    fn test_safe_modules() {
        let policy = ScanPolicy::default_policy();
        assert_eq!(policy.evaluate_internal("collections", "OrderedDict"), PolicyVerdict::Safe);
        assert_eq!(policy.evaluate_internal("numpy", "ndarray"), PolicyVerdict::Safe);
        assert_eq!(policy.evaluate_internal("torch", "FloatTensor"), PolicyVerdict::Safe);
    }

    #[test]
    fn test_explicit_allow_overrides() {
        let mut policy = ScanPolicy::default_policy();
        policy.allow("custom_module", "safe_func");
        assert_eq!(policy.evaluate_internal("custom_module", "safe_func"), PolicyVerdict::Safe);
    }

    #[test]
    fn test_strict_mode() {
        let policy = ScanPolicy::strict_policy();
        assert_eq!(policy.evaluate_internal("unknown_module", "func"), PolicyVerdict::Suspicious);
    }

    #[test]
    fn test_private_names_suspicious() {
        let policy = ScanPolicy::default_policy();
        assert_eq!(policy.evaluate_internal("some_module", "_hidden"), PolicyVerdict::Suspicious);
    }
}
