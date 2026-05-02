# Troubleshooting

## JSON Output Is Not Valid

Use `-f json` and redirect stderr separately:

```bash
sentinel scan ./project -f json > out.json 2> human.log
python -m json.tool out.json
```

If stdout contains Rich/table text, file a bug with the exact command.

## Optional Dependency Missing

Install the matching extra:

```bash
pip install "eresus-sentinel[hf]"
pip install "eresus-sentinel[web]"
pip install "eresus-sentinel[archive]"
```

Run `sentinel doctor --json` to see unavailable scanners.

## Dashboard Shows UI Build Missing

When running from source:

```bash
cd frontend
npm install
npm run build
```

Then restart `sentinel dashboard`.

## Network Scans Fail in CI

Set offline mode for deterministic CI gates:

```bash
export SENTINEL_OFFLINE=1
export HF_HUB_OFFLINE=1
```

Live HF/cloud tests should stay integration-marked.
