# Agentilizer

Static analysis for **Excessive Data Exposure (EDE)** in [n8n](https://n8n.io) workflow automations. Agentilizer reads an exported workflow JSON, compares the fields each node transmits against the minimum set required by n8n's own source code, and flags the surplus — including unnecessary personal data (PII) relevant to GDPR Article 5(1)(c) data minimisation.

Companion artefact to the paper:

> O. Illiashenko and S. Ali, "Measuring Excessive Data Exposure in Agentic AI Workflow Automation: A Field-Level Empirical Study of n8n Workflows," *16th IEEE International Conference on Dependable Systems, Services and Technologies (DESSERT)*, Corfu, Greece, 2026.

## What it measures

For each node, **EDE = (transmitted fields that are not required) / (transmitted fields)**. A node that forwards a whole CRM contact record to an email step needing only three fields scores high; a node that sends only what it needs scores 0.

Across 20,546 public workflows (334,341 node instances), the study found a mean EDE of **50.75%** on externally transmitting nodes, with **92.3%** of those workflows sending at least one unnecessary field and **2,165** unnecessary PII transmissions. Official templates over-expose as much as community ones, pointing to a platform-level pattern rather than individual error.

## How it works

A single calculation engine drives both the batch corpus pipeline and the web app, so interactive audits and reported figures come from identical code:

```
batch_analyze.py / views.py
  └─ ede_service.run_ede_audit
       └─ ede_audit_tool.analyse_workflow
            ├─ node_scope      classify node (egress / ai / internal / trigger)
            ├─ exposure_core   compute the EDE ratio
            └─ pii_taxonomy    flag unnecessary PII
```

- **Minimum Field Registry** — parsed from the `n8n-nodes-base` TypeScript source: 2,464 field records across 523 nodes, 817 required, 4,131 operation–resource combinations. Stored in `data/ede_research_v2.db`.
- **Scope classifier** — only nodes that transmit data to an external service or AI provider count toward the data-minimisation result.
- **PII taxonomy** — a conservative, name-based classifier that flags a field only when its name alone indicates personal data, keeping the count a defensible lower bound.

## Features

- **Web app (Django)** — upload one or more workflow JSON files and get a two-panel evidence view per node: the source-derived *required* fields on the left, the *actual payload* on the right, every field annotated `REQUIRED` / `SURPLUS` / `PII` / `EXPRESSION`, alongside the EDE ratio.
- **Batch dashboard** — audit an entire corpus and view aggregate EDE, the severity distribution, and PII counts.
- **Reproducible pipeline** — rebuild the registry and regenerate the figures reported in the paper.

## Quick start

```bash
git clone https://github.com/alihussain6692/agentilizer.git
cd agentilizer
python -m venv venv && source venv/bin/activate     # Windows: venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

Open <http://127.0.0.1:8000>, upload a workflow JSON exported from n8n, and review the audit.

## Reproducing the study

The corpus is drawn from six public repositories — the n8n.io template library, `zengfr/n8n-workflow-all-templates`, `ritik-prog/n8n-automation-templates-5000`, `Zie619/n8n-workflows`, `Danitilahun/n8n-workflow-templates`, and `enescingoz/awesome-n8n-templates`. It is not redistributed here.

Run the pipeline scripts in `scripts/` in order (`research_step4*` through `research_step8`) to build `ede_research_v2.db` and emit the result tables.

## Project layout

```
agentilizer/      Django project (settings, urls)
audit/            web app: views, templates, static assets
scripts/          analysis engine and research pipeline
    ede_audit_tool.py   exposure_core.py   node_scope.py
    pii_taxonomy.py     db_setup.py        ede_service.py
    batch_analyze.py    research_step*.py
data/             ede_research_v2.db (registry + results)
tests/            pytest suite
```

## Tests

```bash
pytest
```

## Citation

```bibtex
@inproceedings{illiashenko2026ede,
  title     = {Measuring Excessive Data Exposure in Agentic AI Workflow Automation:
               A Field-Level Empirical Study of n8n Workflows},
  author    = {Illiashenko, Oleg and Ali, Shoaib},
  booktitle = {16th IEEE International Conference on Dependable Systems,
               Services and Technologies (DESSERT)},
  address   = {Corfu, Greece},
  year      = {2026}
}
```

## Acknowledgements

Developed at the School of Built Environment, Engineering and Computing, Leeds Beckett University, under the supervision of Dr. Oleg Illiashenko.

## License

See [`LICENSE`](LICENSE). MIT is a common choice for research tooling; confirm before publishing.
