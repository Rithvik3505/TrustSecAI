# TrustSecAI Run Commands

Canonical project root:

```powershell
cd "C:\Users\LENOVO\WORK\Projects\TrustSecAI\TrustSecAI"
```

## 1. Start Neo4j

Open a separate terminal and run:

```powershell
cd "C:\Users\LENOVO\WORK\Projects\TrustSecAI\TrustSecAI\tools\runtime\neo4j\neo4j-community-5.26.0\bin"
.\neo4j.bat console
```

Keep this terminal open while running graph-backed demo commands.

## 2. Set Neo4j URI For Local Demo Commands

In the project terminal, use IPv4 explicitly:

```powershell
cd "C:\Users\LENOVO\WORK\Projects\TrustSecAI\TrustSecAI"
$env:NEO4J_URI="bolt://127.0.0.1:7687"
```

If needed, also set credentials:

```powershell
$env:NEO4J_USER="neo4j"
$env:NEO4J_PASSWORD="password"
```

## 3. Regenerate Offline Demo Reports

These commands do **not** run LoRA inference. They read frozen LoRA compact outputs from:

```text
artifacts/evaluation/lora_v1/lora_generations_compact.jsonl
```

Run all five graph-backed demo cases:

```powershell
python -m src.pipeline.trustsecai_demo --example-id trustsecai-gold-v1-00575 --offline-lora --use-graph-attack-chain
python -m src.pipeline.trustsecai_demo --example-id trustsecai-gold-v1-00178 --offline-lora --use-graph-attack-chain
python -m src.pipeline.trustsecai_demo --example-id trustsecai-gold-v1-00810 --offline-lora --use-graph-attack-chain
python -m src.pipeline.trustsecai_demo --example-id trustsecai-gold-v1-00381 --offline-lora --use-graph-attack-chain
python -m src.pipeline.trustsecai_demo --example-id trustsecai-gold-v1-00128 --offline-lora --use-graph-attack-chain
```

Generated outputs:

```text
artifacts/demo/demo_trustsecai-gold-v1-00575.json
artifacts/demo/demo_trustsecai-gold-v1-00575.md
artifacts/demo/demo_trustsecai-gold-v1-00178.json
artifacts/demo/demo_trustsecai-gold-v1-00178.md
artifacts/demo/demo_trustsecai-gold-v1-00810.json
artifacts/demo/demo_trustsecai-gold-v1-00810.md
artifacts/demo/demo_trustsecai-gold-v1-00381.json
artifacts/demo/demo_trustsecai-gold-v1-00381.md
artifacts/demo/demo_trustsecai-gold-v1-00128.json
artifacts/demo/demo_trustsecai-gold-v1-00128.md
```

## 4. Verify Attack-Chain Mode

Run:

```powershell
@'
import json
from pathlib import Path

ids = [
    "trustsecai-gold-v1-00575",
    "trustsecai-gold-v1-00178",
    "trustsecai-gold-v1-00810",
    "trustsecai-gold-v1-00381",
    "trustsecai-gold-v1-00128",
]

for eid in ids:
    data = json.loads(Path(f"artifacts/demo/demo_{eid}.json").read_text(encoding="utf-8"))
    chain = data.get("attack_chain_prediction", {})
    print(data["metadata"]["ids_label"], eid, chain.get("mode"), chain.get("graph_available"))
'@ | python -
```

Expected when Neo4j is running:

```text
Web Attack - Sql Injection trustsecai-gold-v1-00575 graph True
PortScan trustsecai-gold-v1-00178 graph True
FTP-Patator trustsecai-gold-v1-00810 graph True
Bot trustsecai-gold-v1-00381 graph True
DDoS trustsecai-gold-v1-00128 graph True
```

## 5. Run Streamlit UI

Install Streamlit if needed:

```powershell
pip install streamlit
```

Run the UI:

```powershell
cd "C:\Users\LENOVO\WORK\Projects\TrustSecAI\TrustSecAI"
streamlit run src/ui/streamlit_demo.py
```

The UI is offline-first. It reads existing files from:

```text
artifacts/demo/
```

It does not require GPU and does not run LoRA inference.

## 6. Run Live Classifier Demo

This is classifier-only live inference. It does not run LoRA, Neo4j, GraphRAG, or attack-chain prediction.

Run the Streamlit classifier demo:

```powershell
cd "C:\Users\LENOVO\WORK\Projects\TrustSecAI\TrustSecAI"
python -m streamlit run src/ui/classifier_live_demo.py
```

CLI fallback by label:

```powershell
python -m src.pipeline.classifier_live_predict --label PortScan
```

CLI deterministic random sample:

```powershell
python -m src.pipeline.classifier_live_predict --random
```

CLI by row number from `artifacts/demo/classifier_live_samples.csv`:

```powershell
python -m src.pipeline.classifier_live_predict --row-number 1
```

The live classifier demo uses:

```text
models/xgboost/xgboost_model.joblib
models/xgboost/feature_order.json
artifacts/demo/classifier_live_samples.csv
```

## 7. Run End-to-End Local Demo

This runs the lightweight parts live and uses frozen LoRA output from the completed HPC evaluation.

Live components:

```text
classifier, feature extraction, report assembly, agreement analysis, attack-chain logic
```

Cached component:

```text
LoRA text generation from artifacts/evaluation/lora_v1/lora_generations_compact.jsonl
```

Run the Streamlit end-to-end demo:

```powershell
cd "C:\Users\LENOVO\WORK\Projects\TrustSecAI\TrustSecAI"
.venv\Scripts\python.exe -m pip install streamlit neo4j
$env:NEO4J_URI="bolt://127.0.0.1:7687"
.venv\Scripts\python.exe -m streamlit run src/ui/end_to_end_live_demo.py
```

The app has two tabs:

```text
End-to-End Demo
Live Classifier Sandbox
```

Use `Live Classifier Sandbox` to edit CICIDS feature values and rerun the saved XGBoost classifier live. This sandbox is classifier-only and does not require Neo4j, LoRA, GPU, or Llama.

If the UI still shows `static_fallback` after Neo4j starts, stop the Streamlit server with `Ctrl+C` and launch it again from the same terminal. Environment variables are read by the Streamlit server process when it starts.

Quick graph-mode CLI check using the same environment as Streamlit:

```powershell
$env:NEO4J_URI="bolt://127.0.0.1:7687"
.venv\Scripts\python.exe -m src.pipeline.end_to_end_live_demo --example-id trustsecai-gold-v1-00128
```

Expected:

```text
"attack_chain_mode": "graph"
```

CLI fallback by known example:

```powershell
python -m src.pipeline.end_to_end_live_demo --example-id trustsecai-gold-v1-00575
```

CLI fallback by label:

```powershell
python -m src.pipeline.end_to_end_live_demo --label PortScan
```

CLI fallback with manual feature overrides:

```powershell
python -m src.pipeline.end_to_end_live_demo --example-id trustsecai-gold-v1-00575 --override-feature "Destination Port=443" --override-feature "Average Packet Size=60"
```

Force static fallback for attack-chain logic:

```powershell
python -m src.pipeline.end_to_end_live_demo --label PortScan --no-graph-attack-chain
```

Generated outputs:

```text
artifacts/demo/live_end_to_end/
```

## 8. Recommended Files To Open For Review

```text
reports/demo_readme.md
reports/final_project_status.md
reports/final_demo_summary.md
reports/demo_case_index.md
reports/agreement_analysis.md
reports/attack_chain_agent.md
reports/attack_chain_graph_extension.md
reports/ui_demo_guide.md
reports/classifier_live_demo_guide.md
reports/end_to_end_live_demo_guide.md
```

Recommended first demo report:

```text
artifacts/demo/demo_trustsecai-gold-v1-00575.md
```

Final report and PPT:

```text
reports/trustsecai_ieee_report_final.docx
reports/TrustSecAI_Final_Review_Presentation.pptx
```

## 9. Important Safety Notes

Do not rerun these unless explicitly required:

```text
LoRA training
LoRA full inference
XGBoost retraining
Graph ingestion
Dataset preprocessing
```

Do not modify or delete:

```text
models/lora/trustsecai_lora_v1/
models/lora/trustsecai_lora_v1/checkpoint-100/
models/lora/trustsecai_lora_v1/checkpoint-125/
models/lora/trustsecai_lora_v1/checkpoint-129/
artifacts/training/
artifacts/evaluation/
artifacts/processed/
```
