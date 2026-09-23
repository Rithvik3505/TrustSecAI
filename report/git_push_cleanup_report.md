# Git Push Cleanup Report

## 1. Initial Git State

- Repository: TrustSecAI
- Branch: `main`
- Original local root commit: `85d586ee` (`finished project`)
- Remote: `https://github.com/Rithvik3505/TrustSecAI.git`
- Remote state before cleanup: empty (no branch heads returned by `git ls-remote --heads origin`)
- Initial tracked files: 16,978
- Initial packed Git size: 5.60 GiB
- Initial history: one local root commit

Because the remote was empty and the repository contained only one local commit, the cleanup used a root-commit amendment instead of a multi-commit filter-repo rewrite.

## 2. Largest Files Inspected

All entries below were tracked before cleanup. `Exclude` means the file remains on local disk but is no longer tracked because it is downloaded, generated, reproducible, duplicated, environment-specific, or too large for normal Git hosting.

| # | Size (MiB) | Initially tracked | Decision | Path |
|---:|---:|:---:|:---:|---|
| 1 | 2018.26 | Yes | Exclude | `artifacts/corpus/trustsecai_sft_30k_pretty.json` |
| 2 | 2017.92 | Yes | Exclude | `artifacts/corpus/final_dataset_pretty.json` |
| 3 | 2017.92 | Yes | Exclude | `artifacts/corpus/trustsecai_sft_v1_30k_pretty.json` |
| 4 | 1480.99 | Yes | Exclude | `trustsecai_lora_v1_backup.tar.gz` |
| 5 | 1429.76 | Yes | Exclude | `artifacts/corpus/trustsecai_sft_30k.jsonl` |
| 6 | 1429.54 | Yes | Exclude | `artifacts/corpus/trustsecai_sft_v1_30k.jsonl` |
| 7 | 1429.54 | Yes | Exclude | `artifacts/corpus/final_dataset.jsonl` |
| 8 | 320.37 | Yes | Exclude | `models/lora/trustsecai_lora_v1/checkpoint-129/optimizer.pt` |
| 9 | 320.37 | Yes | Exclude | `models/lora/trustsecai_lora_v1/checkpoint-125/optimizer.pt` |
| 10 | 320.37 | Yes | Exclude | `models/lora/trustsecai_lora_v1/checkpoint-100/optimizer.pt` |
| 11 | 320.37 | Yes | Exclude | `models/lora/trustsecai_lora_v1_dry_run/checkpoint-5/optimizer.pt` |
| 12 | 305.21 | Yes | Exclude | `artifacts/processed/cleaned_cicids.parquet` |
| 13 | 214.74 | Yes | Exclude | `Datasets/CICIDS-2017/Wednesday-workingHours.pcap_ISCX.csv` |
| 14 | 181.97 | Yes | Exclude | `tools/downloads/OpenJDK17.zip` |
| 15 | 168.73 | Yes | Exclude | `Datasets/CICIDS-2017/Monday-WorkingHours.pcap_ISCX.csv` |
| 16 | 160.06 | Yes | Exclude | `models/lora/trustsecai_lora_v1/checkpoint-129/adapter_model.safetensors` |
| 17 | 160.06 | Yes | Exclude | `models/lora/trustsecai_lora_v1/adapter_model.safetensors` |
| 18 | 160.06 | Yes | Exclude | `models/lora/trustsecai_lora_v1/checkpoint-100/adapter_model.safetensors` |
| 19 | 160.06 | Yes | Exclude | `models/lora/trustsecai_lora_v1/checkpoint-125/adapter_model.safetensors` |
| 20 | 160.06 | Yes | Exclude | `models/lora/trustsecai_lora_v1_dry_run/adapter_model.safetensors` |
| 21 | 160.06 | Yes | Exclude | `models/lora/trustsecai_lora_v1_dry_run/checkpoint-5/adapter_model.safetensors` |
| 22 | 151.48 | Yes | Exclude | `tools/downloads/neo4j-community-5.26.0-windows.zip` |
| 23 | 136.94 | Yes | Exclude | `.venv/Lib/site-packages/xgboost/lib/xgboost.dll` |
| 24 | 128.82 | Yes | Exclude | `Datasets/CICIDS-2017/Tuesday-WorkingHours.pcap_ISCX.csv` |
| 25 | 122.77 | Yes | Exclude | `tools/runtime/jdk17/jdk-17.0.19+10/lib/modules` |
| 26 | 79.25 | Yes | Exclude | `Datasets/CICIDS-2017/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` |
| 27 | 73.55 | Yes | Exclude | `Datasets/CICIDS-2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` |
| 28 | 73.34 | Yes | Exclude | `Datasets/CICIDS-2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` |
| 29 | 61.71 | Yes | Exclude | `tools/runtime/neo4j/neo4j-community-5.26.0/data/transactions/neo4j/neostore.transaction.db.0` |
| 30 | 55.62 | Yes | Exclude | `Datasets/CICIDS-2017/Friday-WorkingHours-Morning.pcap_ISCX.csv` |
| 31 | 50.81 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-19.1.json` |
| 32 | 50.81 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack.json` |
| 33 | 50.24 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-19.0.json` |
| 34 | 49.75 | Yes | Exclude | `models/random_forest/random_forest_model.joblib` |
| 35 | 49.61 | Yes | Exclude | `Datasets/CICIDS-2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` |
| 36 | 48.53 | Yes | Exclude | `tools/runtime/jdk17/jdk-17.0.19+10/lib/src.zip` |
| 37 | 48.43 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-18.0.json` |
| 38 | 48.36 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-18.1.json` |
| 39 | 44.33 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-16.1.json` |
| 40 | 44.33 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-16.0.json` |
| 41 | 42.80 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-17.1.json` |
| 42 | 42.03 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-17.0.json` |
| 43 | 41.46 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-15.1.json` |
| 44 | 41.46 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-15.0.json` |
| 45 | 39.84 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-14.1.json` |
| 46 | 39.84 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-14.0.json` |
| 47 | 38.33 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-13.1.json` |
| 48 | 38.33 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-13.0.json` |
| 49 | 36.44 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-12.1.json` |
| 50 | 36.44 | Yes | Exclude | `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack-12.0.json` |

## 3. Largest Historical Blobs

The largest historical blobs matched the tracked files above. The leading blobs were:

| Size (MiB) | Object | Path |
|---:|---|---|
| 1975.98 | `db51c506e193a186699c19f0e2e790a6e9814ded` | `artifacts/corpus/trustsecai_sft_30k_pretty.json` |
| 1975.66 | `317c1fc1967aea06614c0a38f163244cac1f122e` | `artifacts/corpus/final_dataset_pretty.json` and duplicate v1 path |
| 1480.99 | `b9fbd2aeebd10bda94dac299bc32a8c0e99760d5` | `trustsecai_lora_v1_backup.tar.gz` |
| 1429.76 | `d832c8587e106d872a9ad90b5773adf0df988f99` | `artifacts/corpus/trustsecai_sft_30k.jsonl` |
| 1429.54 | `b7f8f2d37a84e5118ab24f01ec841d6792d370f5` | final/v1 30k JSONL corpus exports |
| 320.37 | multiple | LoRA optimizer checkpoint states |
| 305.21 | `8c83b9797c6139030479365d3d2f1071caf6b8d5` | `artifacts/processed/cleaned_cicids.parquet` |
| 214.74 | `c86611eee8142a5ce1e774a8b5539c5f30de81f5` | CICIDS Wednesday CSV |
| 181.97 | `922acbbd2fc4a512e46dad0edc313039dec9a54c` | OpenJDK installer archive |
| 160.06 | multiple | LoRA adapter/checkpoint weights |

After cleanup, none of these blobs remains reachable in Git history.

## 4. Files Kept in Git

The final repository keeps:

- all source code under `src/`;
- project commands and configuration, including `run_cmd.md` and training configuration;
- all Markdown reports, IEEE deliverables, presentation files, diagrams, and screenshots;
- small metrics, graph summaries, mappings, SHAP summaries, retrieval contexts, and demo outputs;
- the compact LoRA evaluation generation file and evaluation metrics;
- evidence-expansion summaries and compact review samples;
- the strict reviewed SFT corpus and its leakage-safe train/validation/test splits;
- the compact cleaned CICIDS demo sample used by live classifier demonstrations;
- the 1.54 MiB XGBoost model plus feature order and metadata required by the live demo;
- small documentation under `Docs/`.

Final tracked set before this report: 344 files, approximately 41.70 MiB uncompressed.

## 5. Files Excluded from Git

The cleanup excludes:

- downloaded CICIDS, ATT&CK, CAPEC, and NVD source datasets;
- full processed Parquet datasets;
- multi-gigabyte synthetic corpora and duplicate pretty exports;
- duplicate/superseded gold-candidate exports and review workbooks;
- derived SFT formatting copies;
- LoRA adapters, checkpoints, optimizer states, and dry-run model outputs;
- the large Random Forest model binary;
- Neo4j and JDK runtimes, installers, and Neo4j database storage;
- virtual environments, Python caches, test/tool caches, logs, and local OS/editor metadata;
- the local LoRA backup archive.

## 6. Files Untracked but Preserved Locally

No project file was physically removed. Spot checks after untracking confirmed that the following remained present locally:

- `trustsecai_lora_v1_backup.tar.gz` (1480.99 MiB)
- `artifacts/corpus/trustsecai_sft_30k_pretty.json` (2018.26 MiB)
- `artifacts/processed/cleaned_cicids.parquet` (305.21 MiB)
- `models/lora/trustsecai_lora_v1/adapter_model.safetensors` (160.06 MiB)
- `models/lora/trustsecai_lora_v1/checkpoint-129/optimizer.pt` (320.37 MiB)
- `Datasets/CICIDS-2017/Wednesday-workingHours.pcap_ISCX.csv` (214.74 MiB)
- `tools/downloads/OpenJDK17.zip` (181.97 MiB)
- Neo4j database files under `tools/runtime/neo4j/`

## 7. `.gitignore` Changes

A repository-level `.gitignore` was added. It uses scoped patterns for environments/caches, secrets, logs, downloaded datasets, local runtimes, processed Parquet data, generated corpora, superseded gold-candidate exports, derived SFT files, superseded evaluation runs, large model outputs, and the backup archive. It does not blanket-ignore `artifacts/` or `models/`; useful small results and the XGBoost live-demo model remain tracked.

## 8. History Cleanup Performed

The repository had one local root commit and an empty remote. The index was rebuilt using `.gitignore`, then the root commit was amended from `85d586ee` to `6df0b731`. Reflogs were expired and unreachable objects were pruned with Git garbage collection. No force push was needed.

## 9. Content and Preservation Verification

- No tracked `.py`, report `.md`, JSON, CSV, model, dataset, or configuration content was edited during cleanup.
- The only project-tree content added before the first push was `.gitignore`.
- Git showed no modified tracked-content blobs during the index rebuild; changes were deletions from tracking plus `.gitignore`.
- `git fsck --full --no-reflogs` completed without errors.
- Excluded large files were verified as present locally and absent from `git ls-files`.

## 10. Secret Scan Result

The final tracked tree and cleaned history were scanned for obvious private-key headers, GitHub tokens, OpenAI keys, Hugging Face tokens, AWS access keys, sensitive `.env` filenames, and common private-key filenames. No matches were found. Secret values were never printed.

## 11. Final Repository Size and Limits

- Final packed Git size before adding this report: 15.37 MiB
- Largest remaining Git blob: 6.53 MiB (`artifacts/gold_candidates/v1/reviewed/trustsecai_gold_v1_reviewed.jsonl`)
- Files above GitHub's 100 MiB per-file limit: 0
- Final push size: comfortably below 2 GiB
- Final reachable history: one cleaned root commit before this report commit

## 12. Push Result

- Initial cleaned push: successful
- Command: `git push -u origin main`
- Branch created: `origin/main`
- Force push used: no
- Repository URL: https://github.com/Rithvik3505/TrustSecAI

