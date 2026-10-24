# Feature-Guided Selective Migration of Volatility 3 Plugins to Rust

This repository contains the source code, evaluation scripts, and experimental benchmarks for the paper:  
**"Feature-Guided Selective Migration of Volatility 3 Plugins to Rust for Windows Memory Forensics"**

## 📌 Overview
This project implements a feature-guided selective migration of core Windows Volatility 3 plugins (`pslist`, `handles`, `svcscan`, `callbacks`, `malfind`) from Python to Rust, evaluating output fidelity, execution runtime, and peak resident set size (RSS).

---

## 📂 Datasets Used

### 1. Development & Feature Selection
* **Primary Source:** [CIC-MalMem-2022 Dataset](https://www.unb.ca/cic/datasets/malmem-2022.html) (Canadian Institute for Cybersecurity)
* **Alternative Mirror:** [Kaggle - Malware Detection from Memory Dump](https://www.kaggle.com/datasets/subhajournal/malware-detection-from-memory-dump/data)

### 2. Testing & Same-Image Evaluation
* **Memory Dumps:** [BCCC-MalMem-SnapLog-2025 Dataset](https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/malware-memory-interval-based-snapshot-dataset-bccc-malmem-snaplog-2025/) (Behaviour-Centric Cybersecurity Center, York University)

---

## 🙏 Acknowledgments & Attribution
* Built upon and inspired by the Volatility 3 framework and prior Rust migration efforts, including [Rusting Volatility (BiTLab-BaggiliTruthLab)](https://github.com/BiTLab-BaggiliTruthLab/Rusting-Volatility3-The-volatile-memory-extraction-framework).
* Developed under the Apache License 2.0.
