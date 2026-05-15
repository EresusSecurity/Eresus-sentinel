# sentinel-pickle-engine

Standalone Rust-backed pickle opcode scanner for Eresus Sentinel.

The PyPI distribution is named `sentinel-pickle-engine`. It builds the
`sentinel_pickle` Python extension with `maturin` and PyO3, with no runtime
dependencies beyond the compiled extension.

The main Sentinel Python scanner imports `sentinel_pickle` opportunistically in
`sentinel.artifact.pickle.scanner`; if the extension is missing, Sentinel falls
back to the pure-Python opcode analyzer unless Rust is explicitly required.

## Build

```bash
cd rust/sentinel-pickle
python -m pip install maturin
maturin develop --release
```

For a wheel:

```bash
cd rust/sentinel-pickle
maturin build --release
```

## Backend Selection

By default Sentinel uses `auto` mode:

- use Rust when `sentinel_pickle` is importable;
- otherwise use the Python analyzer.

Override it with either the constructor or environment:

```python
from sentinel.artifact.pickle_scanner import PickleScanner

PickleScanner(backend="auto")
PickleScanner(backend="rust")
PickleScanner(backend="python")
```

```bash
SENTINEL_PICKLE_BACKEND=rust sentinel artifact suspicious.pkl
SENTINEL_PICKLE_BACKEND=python sentinel artifact suspicious.pkl
```

`rust` mode fails loudly if the extension is not installed. This keeps native
pickle scanning as a separately buildable Python extension instead of hidden
best-effort code.

## Release

The `.github/workflows/pickle-wheels.yml` workflow builds abi3 wheels for Linux
x86_64/aarch64, macOS x86_64/aarch64, and Windows x64. The publish job is wired
for PyPI trusted publishing and sigstore signing; it only runs for GitHub
release events or manual workflow dispatch.

## Fuzzing

Cargo-fuzz targets live in `fuzz/`:

```bash
cd rust/sentinel-pickle
cargo install cargo-fuzz
cargo fuzz run fuzz_scanner
```

See [fuzz/README.md](fuzz/README.md) for target details.
