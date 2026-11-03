# Analyst Tradecraft

This document defines the lightweight analyst tradecraft conventions currently used by ODYSAFE Intelligence Workspace reports.

ODYSAFE does not try to be a generic intelligence ontology, a scoring engine, or an automatic decision system. The goal is to preserve enough context for another analyst to understand why a report exists, what is being claimed, what supports each claim, what remains unknown, what was checked, what limitations apply, and whether the intelligence is relevant to the organization.

These are ODYSAFE application conventions. They are not presented as STIX, MITRE ATT&CK, or intelligence-community standards unless an explicit mapping is implemented elsewhere.

## Current Scope

The current Intelligence Workspace tradecraft layer supports:

- purpose context for the intelligence product;
- collection and data availability planning;
- analytic claims with analytical status, confidence, source references, evidence references, source role, source independence, contradiction references, and decision impact;
- outstanding intelligence gaps;
- internal relevance assessment;
- artifact ownership and sharing context;
- investigation journal entries, including negative findings;
- investigation handoff;
- sharing review and feedback/closure context;
- analytic quality checks;
- Excel export of the tradecraft fields.

Some fields, such as source references and evidence references, are currently free-text references inside the Intelligence Workspace. They are not dedicated database-backed evidence objects.

## Core Principles

Keep analytical dimensions separate:

- analytical status is not confidence;
- source role is not source reliability;
- source reliability is not information credibility;
- source independence is not source count;
- artifact ownership is not attribution;
- internal relevance is not threat severity;
- an investigation result is not a final conclusion;
- decision impact is not action tracking;
- an intelligence gap is not every missing field.

Do not create a magic CTI score. ODYSAFE should flag structural issues and preserve context, not decide truth automatically.

Preserve uncertainty. `UNKNOWN` is valid when the analyst explains what is unknown and why it matters.

Preserve scope for negative findings. `NO_HIT` means no match in the stated data, time window, scope, and coverage. It does not prove that activity never occurred.

## Semantic Contract

The same concept must keep the same meaning in the UI, JSON, and Excel exports.

- an empty field means no value was entered;
- `UNKNOWN` means the analyst explicitly assessed that the answer is currently unknown;
- `NOT_ASSESSED` means the question has not yet been checked;
- `NOT_APPLICABLE` means the question does not make sense in the current context;
- `N/A` is only a visual convenience where the UI needs a compact label for not applicable.

JSON workspace exports use:

- `schema` for the schema identifier;
- `schema_version` for the schema version;
- `workspace_id` for the workspace reference;
- `created_at` and `updated_at` for workspace timestamps;
- `exported_at` for the time the JSON file was produced.

`exported_at` is not an intelligence date, publication date, event date, first seen date, or assessed date.

Excel exports are formatted representations. They must not change the meaning of UI or JSON values.

Saved Intelligence Workspaces use SQLite as the authoritative saved state for the full workspace JSON. Browser localStorage is only draft recovery.

The `Load Sample` action fills the workspace with a fictitious example using reserved values. It is not linked to imported IOC records and should be edited before being treated as an analyst product.

## Interpretation Rules

- Indicator match does not equal compromise.
- `NO_HIT` does not prove absence of activity.
- ATT&CK mapping does not prove internal observation or detection coverage.
- A Sigma rule with an ATT&CK tag does not prove deployed detection coverage.
- External attribution does not become ODYSAFE attribution unless explicitly assessed.
- CVSS severity does not determine internal priority without exposure and relevance context.
- Source reliability does not make every claim from that source reliable.
- Expected outcome is not completion evidence.
- Potential impact is not observed impact.
- Publication readiness means required product information is present. It does not mean the intelligence is correct.

## Core Terms

**Observation**: something directly observed or recorded, such as a log event, command line, packet capture, DNS lookup, malware sample, email, or telemetry record.

**Evidence**: material that supports, weakens, or helps evaluate a claim. Examples include a log entry, PCAP segment, malware sample, command line, screenshot, file, report passage, timeline entry, or internal telemetry record.

**Evidence register**: the workspace table that makes `EVID-*` references resolvable. Each entry records the evidence ID, type, description, source reference, observed time, location/reference, collector, integrity or hash note, and analyst notes.

**Source**: the origin of information, such as a CERT advisory, vendor report, internal DFIR report, researcher publication, internal SOC note, or telemetry source.

**Source reliability**: assessment of the source itself, such as authority, access, consistency, and past reliability. It is separate from whether a specific piece of information is true.

**Information credibility**: assessment of the specific information or claim being used, based on corroboration, plausibility, and evidence quality. It is separate from the source's general reliability.

**Claim**: an individual analytical statement that can be evaluated.

```text
domain.example
```

is an observable.

```text
domain.example was used as C2.
```

is a claim.

**Finding**: the result of an analytical or investigative activity.

**Negative finding**: a search or check was performed and produced no match within a stated scope, time window, and coverage.

**Key judgement**: a high-value analytical conclusion in a report. A key judgement may be supported by multiple claims.

**Intelligence requirement**: the question the intelligence activity is intended to answer.

**Decision requirement**: the decision the intelligence product is intended to support.

**Data availability**: the analyst's stated view of whether a source, telemetry set, or collection path needed for the product is available, missing, partial, or limited.

**Intelligence gap**: an unresolved question that matters for the intelligence requirement or decision requirement.

**Internal relevance**: the degree to which the intelligence applies to the organization. It is separate from threat severity, exposure, internal observation, business criticality, and confidence.

**Investigation handoff**: a concise operational summary that lets another analyst resume the investigation without re-reading the entire case.

**Sharing review**: a pre-distribution check that sensitive internal or victim information, TLP, recipients, and defanging expectations were reviewed.

**Closure**: the analyst's final record of whether the requirement was answered, what outcome the product supported, and what should change next time.

## Data Availability

Data availability records whether the analyst had access to the data needed to answer the intelligence requirement or decision requirement.

Current fields include:

- data source;
- whether the source was needed;
- availability;
- retention;
- coverage;
- limitation.

Data availability is separate from an intelligence gap. A missing data source may create or explain a gap, but it should not automatically create one.

## Evidence Register

The Evidence Register exists to keep claim, timeline, ATT&CK, action, and investigation references traceable.

Current fields include:

- evidence ID;
- type;
- description;
- source reference;
- observed at;
- location or reference;
- collected by;
- integrity or hash;
- notes.

Evidence entries should point back to source references when possible. A claim can still be unknown or inferred even when related evidence exists.

## Artifact Ownership / Context

Artifact ownership describes the operational context of an indicator or artifact.

Allowed values:

- `ATTACKER_CONTROLLED`
- `VICTIM_INTERNAL`
- `BENIGN_ENVIRONMENT`
- `UNKNOWN`

`ATTACKER_CONTROLLED` means the artifact is assessed as controlled or used by the threat activity in the report context.

`VICTIM_INTERNAL` means the artifact belongs to, or appears inside, the victim or organization environment.

`BENIGN_ENVIRONMENT` means the artifact belongs to normal or third-party infrastructure and should not be treated as malicious by itself.

`UNKNOWN` means ownership or context is not established.

Artifact ownership does not prove attribution, compromise, or suitability for blocking.

## Analytical Status

Analytical status applies to a claim, not to the whole report.

Allowed values:

- `OBSERVED`
- `REPORTED`
- `INFERRED`
- `UNKNOWN`

### OBSERVED

The analyst has referenced evidence available in the current ODYSAFE analysis that directly supports the claim.

Minimum expectation: `OBSERVED` should include evidence references.

A vendor report saying "we observed X" does not automatically make the claim `OBSERVED` from ODYSAFE's perspective if the underlying evidence is not available in the current analysis. In that case, the claim may be `REPORTED`.

### REPORTED

A source explicitly states the claim, but the underlying direct observation is not available in the current ODYSAFE analysis.

Minimum expectation: `REPORTED` should include source references.

### INFERRED

The claim is reasoned from other information.

Minimum expectation: `INFERRED` requires a rationale.

### UNKNOWN

The answer is not known with the currently available information.

Minimum expectation: `UNKNOWN` should include an unknown reason.

`UNKNOWN` is not `FALSE`, `NO`, `NO_HIT`, `NOT_ASSESSED`, or `NOT_APPLICABLE`.

## Confidence

Confidence expresses how strongly the analyst currently supports an assessment.

Confidence is separate from analytical status, source role, source independence, internal relevance, and investigation result.

When confidence is important, the analyst should explain the rationale. Intelligence Workspace reports also allow optional fields for what would increase or decrease confidence.

## Source Role

Source role is evaluated in relation to a claim.

Allowed values:

- `PRIMARY`
- `SECONDARY`
- `AGGREGATOR`
- `UNKNOWN`

`PRIMARY` means the source directly produced, observed, collected, or analyzed the underlying information for this claim. It does not mean true, correct, reliable, or independent.

`SECONDARY` means the source analyzes, cites, summarizes, or contextualizes information produced elsewhere.

`AGGREGATOR` means the source primarily collects, republishes, or groups material from other producers.

`UNKNOWN` means the role cannot be determined.

## Source Independence

Source independence is evaluated in relation to a claim or information chain.

Allowed values:

- `INDEPENDENT`
- `DEPENDENT`
- `UNKNOWN`

Multiple publications do not automatically mean multiple independent confirmations. Several articles citing the same original report may still represent one information chain.

When a source is marked `DEPENDENT`, the `Depends On` field should identify the upstream source or information chain when known.

## Contradictory Claims

Intelligence Workspace reports allow a claim to reference another claim through `Conflicts With`.

Contradictions must not be resolved automatically. ODYSAFE should preserve both claims and let the analyst explain or resolve the disagreement.

Before marking claims as contradictory, check whether they actually refer to the same period, campaign, victim population, product/version, infrastructure, or definition.

## Intelligence Gaps

An intelligence gap is an unresolved question that matters for the intelligence requirement or decision requirement.

A gap is not:

- every empty field;
- every `UNKNOWN`;
- a generic note;
- an action;
- a conclusion.

Current Intelligence Workspace gap fields include:

- gap ID;
- question;
- linked requirement;
- related claim;
- why it matters;
- priority;
- what would resolve it;
- owner;
- status;
- resolution summary;
- resolved by references;
- resolved at.

Current statuses:

- `OPEN`
- `RESOLVED`

`RESOLVED` means enough information exists to answer the gap for the requirement or decision. It does not mean absolute truth is known.

## Internal Relevance

Internal relevance asks whether the intelligence applies to the organization.

Current dimensions:

- technology used internally;
- affected version present;
- internet exposure;
- sector relevance;
- geographic relevance;
- supplier relevance;
- internal observation;
- overall relevance;
- relevance decision;
- rationale;
- assessed by;
- assessed at.

State vocabulary:

- `YES`
- `NO`
- `UNKNOWN`
- `NOT_ASSESSED`
- `NOT_APPLICABLE`

`NO` should only be used when a relevant check was performed. If no check was performed, use `NOT_ASSESSED`.

Overall relevance is analyst-assessed. ODYSAFE should not derive it by counting `YES` and `NO` fields.

## Investigation Journal

The Investigation Journal records what the analyst actually did. It unifies pivot history, searches, enrichments, validations, hunts, negative findings, reviews, and notes.

Current entry types:

- `SEARCH`
- `PIVOT`
- `ENRICHMENT`
- `VALIDATION`
- `HUNT`
- `REVIEW`
- `NOTE`

Current result types:

- `HIT`
- `NO_HIT`
- `INCONCLUSIVE`
- `NO_DATA`
- `ERROR`

`NO_HIT` means the search completed successfully and no match was found within the stated scope.

`NO_DATA` means the required data was unavailable.

`INCONCLUSIVE` means the check ran, but the result is ambiguous or insufficient.

`ERROR` means the check could not complete because of a technical or process problem.

For negative findings, include scope, time window, coverage, and limitations.

## Pivot History

A pivot records an investigative transition from one object or attribute to another.

Examples:

- domain to passive DNS to IP;
- IP to certificate to domains;
- hash to malware sample to C2;
- certificate to additional infrastructure.

A pivot is an investigation operation. It does not by itself prove common ownership, campaign linkage, or attribution.

The current implementation stores pivot history as Investigation Journal entries. There is no separate "Already Checked" data store.

## Investigation Handoff

The handoff is a concise operational summary intended to reduce investigation restart cost.

Current fields:

- current situation;
- selected established assessments;
- outstanding questions;
- next recommended step;
- blocked by;
- current owner;
- special warning or context;
- last updated.

Keep the handoff short. It is not a second report.

Prefer "established assessments" or "current findings" over "established facts", because important information may still be `REPORTED` or `INFERRED`.

## Decision Impact

Decision impact identifies which workflow or decision area may be influenced by the intelligence.

Recommended tags:

- `HUNT`
- `DETECTION`
- `VULNERABILITY`
- `INCIDENT_RESPONSE`
- `MONITORING`
- `COLLECTION`
- `SHARING`
- `MANAGEMENT`

Decision impact does not mean an action was executed.

## Quality Checks

Intelligence Workspace reports include an analytic quality check.

The checker validates structural completeness and analytical hygiene. It does not decide whether a claim is true.

Current checks include:

- `OBSERVED` claim without evidence references;
- `REPORTED` claim without source references;
- `INFERRED` claim without rationale;
- `UNKNOWN` claim without unknown reason;
- dependent source chain without an upstream source reference;
- contradiction reference without rationale or note;
- gap without question;
- gap without "why it matters";
- gap without linked requirement when no report-level requirement exists;
- `RESOLVED` gap without resolution summary;
- internal relevance assessment without rationale;
- `IMMEDIATE_ACTION` relevance decision without rationale;
- `NO_HIT` journal entry without scope, time window, telemetry/tool/source, query/method, coverage, or limitations;
- `NO_DATA` journal entry without limitations;
- immediate action without owner;
- block-candidate indicator without confidence, false-positive risk, validation date, or context;
- block-candidate indicator with high false-positive risk;
- expired indicator still marked as a block candidate;
- `TLP:RED` product without a named recipient;
- `TLP:RED` product without verified named recipients in sharing review;
- sharing review without TLP verification;
- defanged export without defanging verification.

The checker reports issues as errors or warnings. It must not produce a quality score.

## Analyst Progress

Analyst Progress describes work coverage, not analysis quality.

Current progress areas are:

- `Purpose`
- `Collection`
- `Analyze`
- `Relevance`
- `Investigate`
- `Assess`
- `Act`
- `Deliver`
- `Close`

Allowed progress states are:

- `NOT STARTED`
- `IN PROGRESS`
- `SUFFICIENT`
- `NEEDS REVIEW`

`SUFFICIENT` means enough work has been documented for the current requirement. It does not mean everything is known.

Analyst Progress must stay separate from Publication Readiness. Publication Readiness indicates whether required product fields are present for the selected product type. Analyst Progress indicates whether the main phases of analyst work have documented coverage.

## Export Behavior

Intelligence Workspace Excel exports preserve the current tradecraft structure, including:

- purpose context;
- data availability planning;
- evidence register;
- analytic claims;
- intelligence gaps;
- internal relevance;
- investigation journal;
- handoff;
- source and evidence references;
- analytical status;
- confidence;
- indicator validation freshness, artifact ownership/context, discriminative value, false-positive risk, review date, and recommended use;
- linked action context, expected outcome, and completion evidence;
- decision impact;
- investigation result type;
- coverage and limitations;
- sharing review;
- feedback and closure.

The workspace can also be exported as JSON. JSON is intended to preserve the full workspace state; Excel is a formatted representation for analysis and sharing.

Saving a workspace also updates the CTI Memory representation with the workspace reference, subject, intelligence requirement, claims, gaps, indicators, TTPs, actions, and investigation journal summaries when Memory indexing is available.

Older reports without these fields should remain loadable with safe defaults such as empty claims, gaps, investigation journal entries, relevance assessment, or handoff data.

## Guardrails

Do not automatically convert confidence into analytical status.

Do not treat multiple dependent sources as independent corroboration.

Do not treat ATT&CK mapping as proof.

Do not treat a pivot as attribution.

Do not treat actor aliases as exact identity without source context.

Do not treat `NO_HIT` as proof of absence.

Do not force every `UNKNOWN` into an intelligence gap.

Do not automatically resolve contradictions.

Do not rank analysts or reports by the number of observed claims, the fewest unknowns, or a completeness percentage.

## Compact Analyst Checklist

Before considering an Intelligence Workspace analytically ready, ask:

- Why does this product exist?
- Who will use it?
- What decision should it support?
- What are the key claims?
- Which claims are observed, reported, inferred, or unknown?
- What evidence supports the important claims?
- Which sources are primary?
- Which sources are actually independent?
- Are any claims contradictory?
- What has already been checked?
- What produced `NO_HIT`?
- What produced `NO_DATA`?
- What were the coverage limitations?
- Which required data sources were unavailable or partial?
- Does this apply to the organization?
- Was internal relevance actually checked?
- What intelligence gaps still matter?
- What would increase or decrease confidence?
- What workflows may be influenced?
- Was the sharing review completed before distribution?
- Did the product answer the original requirement?
- Can another analyst resume the case without starting again?
