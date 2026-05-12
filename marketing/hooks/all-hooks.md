# All Hook Variations — Eresus Sentinel
# Format: hook-generator skill (charlie947/social-media-skills)
# Rule: Line 1 max 40 chars, Line 2 max 40 chars
# Use for: LinkedIn opening lines, Twitter first tweet, email subject lines

---

## TOPIC: Pickle / Model RCE

1. [Number-led]
24 formats. 1 malicious .pkl.
I found RCE in 3 models today.

2. [Contrarian]
Your model file is not data.
It is code. It runs on load.

3. [Personal transformation]
I used to trust every .pkl I downloaded.
Then I read the opcodes.

4. [Authority steal]
PyTorch uses pickle by default.
Google knows this risk. Do you?

5. [Admission]
I shipped a .pkl without scanning it.
Got lucky. It will not happen again.

6. [Future shock]
ML pipelines are the next SolarWinds.
.pkl files are the attack vector.

---

## TOPIC: MCP / Agent Security

1. [Number-led]
11 MCP servers. 0 had validated manifests.
I found 3 permission overreaches.

2. [Contrarian]
MCP is not just an API protocol.
It is an open door if you skip validation.

3. [Personal transformation]
I ran MCP agents blind for 3 months.
A proxy changed everything.

4. [Authority steal]
Anthropic built MCP for scale.
Nobody built the security layer yet.

5. [Admission]
I gave an MCP server full file access.
I did not know I had done it.

6. [Future shock]
Agent security is 2 years behind adoption.
The attacks are already here.

---

## TOPIC: Prompt Injection

1. [Number-led]
80% of LLM apps have no input guard.
I tested 12 this month. 10 failed.

2. [Contrarian]
Prompt injection is not a model bug.
It is your architecture's problem.

3. [Personal transformation]
I thought my system prompt was safe.
One injection proved otherwise.

4. [Authority steal]
OWASP lists it as the #1 LLM risk.
Most teams still have not acted on that.

5. [Admission]
I shipped an LLM app with no firewall.
The first test broke everything.

6. [Future shock]
LLM firewalls will be table stakes.
By 2027, ships without one get penalised.

---

## TOPIC: AI DevSecOps / SAST

1. [Number-led]
47 secrets. 1 AI codebase. 1 afternoon.
The team had no idea they were there.

2. [Contrarian]
SAST for AI is not the same as for web apps.
Your AI code has different attack paths.

3. [Personal transformation]
Pre-commit hooks felt like overkill.
They caught 3 API keys before git push.

4. [Authority steal]
GitHub Advanced Security costs money.
SARIF output is open and free.

5. [Admission]
I merged a PR with 3 API keys in it.
Found them 6 hours after deploy.

6. [Future shock]
AI code ships faster than it is audited.
The gap is where the breaches live.

---

## TOPIC: HuggingFace Supply Chain

1. [Number-led]
1 in 10 models I scanned was flagged.
None were labelled as malicious.

2. [Contrarian]
HuggingFace is not a safe model store.
It is a registry with no upload gate.

3. [Personal transformation]
I used to download and load directly.
Now I scan first. Takes 3 seconds.

4. [Authority steal]
HuggingFace hosts 1M+ models.
Malware hides in the weights.

5. [Admission]
I shipped a model I never audited.
Found trust_remote_code=True later.

6. [Future shock]
Model supply chains are the new NPM.
Leftpad but with RCE potential.
