"""
Fetch the MITRE ATT&CK for ICS technique matrix (STIX 2.1 bundle).

Source: https://github.com/mitre-attack/attack-stix-data/tree/master/ics-attack
License: MITRE ATT&CK content is released for public use under the Terms of
Use at https://attack.mitre.org/resources/terms-of-use/ (attribution required).

CHANGED IN v1.1: v1.0 fetched the technique list into
data/raw/attack_ics_techniques.csv but never joined it into the dataset —
join.py never referenced it, despite the README and Zenodo description both
listing ATT&CK for ICS as an integrated source. ATT&CK for ICS techniques
don't map to CVE IDs directly (a technique is "how", not tied to a specific
vulnerability), so a per-CVE join has to go through something ATT&CK for ICS
DOES name explicitly: threat groups (`intrusion-set`) and malware/tools
(`malware`/`tool`), whose STIX descriptions frequently name the real-world
vendor/product they were built to target (e.g. "TRITON ... targeted
Schneider Electric Triconex safety controllers"). v1.1 fetches those objects
plus the `uses` relationships linking each to specific technique IDs, so
src/join.py can tag a dataset row only where its Vendor/Product text is
explicitly named in a group's or software's own ATT&CK description — an
auditable, row-by-row match, not a bulk inference. See NEXT_STEPS.md (v1.0)
for why this approach was chosen over a class-level technique mapping.
"""
from __future__ import annotations
import requests
import pandas as pd

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/ics-attack/ics-attack.json"
)


def _external_id(obj: dict) -> str | None:
    return next(
        (r["external_id"] for r in obj.get("external_references", [])
         if r.get("source_name") == "mitre-attack"),
        None,
    )


def fetch_techniques(bundle: dict | None = None, session: requests.Session | None = None) -> pd.DataFrame:
    bundle = bundle or _fetch_bundle(session)
    rows = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        rows.append({
            "technique_id": _external_id(obj),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "tactic_phases": ", ".join(p["phase_name"] for p in obj.get("kill_chain_phases", [])),
        })
    return pd.DataFrame(rows)


def fetch_groups_and_software(bundle: dict | None = None, session: requests.Session | None = None) -> pd.DataFrame:
    """Intrusion-set (threat group) and malware/tool objects, each with the
    technique IDs it's linked to via a STIX `uses` relationship.

    Returns one row per group/software entry with: stix_id, entity_type
    (group|software), name, description, external_id (e.g. G0088, S1009),
    technique_ids (comma-joined technique IDs this entity `uses`).
    """
    bundle = bundle or _fetch_bundle(session)
    objects = bundle.get("objects", [])

    technique_ext_id_by_stix_id = {
        obj["id"]: _external_id(obj)
        for obj in objects
        if obj.get("type") == "attack-pattern"
    }

    entity_types = {"intrusion-set", "malware", "tool"}
    entities = {
        obj["id"]: obj for obj in objects
        if obj.get("type") in entity_types and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
    }

    technique_ids_by_entity: dict[str, list[str]] = {stix_id: [] for stix_id in entities}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        source_ref, target_ref = obj.get("source_ref"), obj.get("target_ref")
        if source_ref in technique_ids_by_entity and target_ref in technique_ext_id_by_stix_id:
            ext_id = technique_ext_id_by_stix_id[target_ref]
            if ext_id:
                technique_ids_by_entity[source_ref].append(ext_id)

    rows = []
    for stix_id, obj in entities.items():
        rows.append({
            "stix_id": stix_id,
            "entity_type": "group" if obj["type"] == "intrusion-set" else "software",
            "name": obj.get("name"),
            "description": obj.get("description", ""),
            "external_id": _external_id(obj),
            "technique_ids": ", ".join(sorted(set(technique_ids_by_entity.get(stix_id, [])))),
        })
    return pd.DataFrame(rows)


def _fetch_bundle(session: requests.Session | None = None) -> dict:
    session = session or requests.Session()
    session.headers.update({"User-Agent": "ong-ot-dataset-pipeline/1.1"})
    resp = session.get(STIX_URL, timeout=60)
    resp.raise_for_status()
    return resp.json()


if __name__ == "__main__":
    bundle = _fetch_bundle()
    techniques = fetch_techniques(bundle)
    groups_software = fetch_groups_and_software(bundle)
    print(techniques.shape, "technique rows")
    print(groups_software.shape, "group/software rows")
    techniques.to_csv("data/raw/attack_ics_techniques.csv", index=False)
    groups_software.to_csv("data/raw/attack_ics_groups_software.csv", index=False)
