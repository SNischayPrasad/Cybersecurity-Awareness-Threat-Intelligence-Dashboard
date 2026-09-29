"""
Threat Correlation Engine
=========================

Groups threat records that share evidence into RELATED THREAT CLUSTERS.

Link rules (either one links two records):
  1. Same campaign_id AND overlapping observation windows (within `window_days`)
  2. Same indicator value (e.g., the same IP reported by two different feeds)

IMPORTANT: correlation shows a *relationship in the evidence*.
It does NOT prove attribution - it does not tell us WHO is behind activity.
"""
from __future__ import annotations

from datetime import date

CORRELATION_NOTE = ("Correlation indicates related evidence (shared campaign or indicator). "
                    "It is not proof of attribution to any actor.")


class _UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]  # path compression
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _windows_overlap(a: dict, b: dict, window_days: int) -> bool:
    a1, a2 = date.fromisoformat(a["first_seen"]), date.fromisoformat(a["last_seen"])
    b1, b2 = date.fromisoformat(b["first_seen"]), date.fromisoformat(b["last_seen"])
    gap = max((b1 - a2).days, (a1 - b2).days, 0)
    return gap <= window_days


def correlate_threats(records: list[dict], window_days: int = 60, min_size: int = 2) -> list[dict]:
    """Cluster records. Each record needs: threat_id, indicator_value, indicator_type,
    category, campaign_id, first_seen, last_seen, risk_score, confidence_score."""
    uf = _UnionFind()
    reasons = {}
    by_campaign, by_indicator = {}, {}
    for r in records:
        uf.find(r["threat_id"])
        if r.get("campaign_id"):
            by_campaign.setdefault(r["campaign_id"], []).append(r)
        by_indicator.setdefault((r.get("indicator_value") or "").lower(), []).append(r)

    for members in by_campaign.values():
        for i, a in enumerate(members):
            for b in members[i + 1:]:
                if _windows_overlap(a, b, window_days):
                    uf.union(a["threat_id"], b["threat_id"])
                    reasons.setdefault(uf.find(a["threat_id"]), set()).add("shared campaign_id")
    for value, members in by_indicator.items():
        if value and len(members) > 1:
            first = members[0]["threat_id"]
            for other in members[1:]:
                uf.union(first, other["threat_id"])
            reasons.setdefault(uf.find(first), set()).add("shared indicator value")

    groups = {}
    for r in records:
        groups.setdefault(uf.find(r["threat_id"]), []).append(r)
    # Reasons may have been recorded under an old root before later unions: re-key them.
    root_reasons = {}
    for old_root, rs in reasons.items():
        root_reasons.setdefault(uf.find(old_root), set()).update(rs)

    clusters = []
    for root, members in groups.items():
        if len(members) < min_size:
            continue
        risks = [m["risk_score"] for m in members]
        confs = [m["confidence_score"] for m in members]
        link = root_reasons.get(root, set())
        clusters.append({
            "threat_ids": sorted(m["threat_id"] for m in members),
            "size": len(members),
            "indicators": sorted({m["indicator_value"] for m in members}),
            "indicator_types": sorted({m["indicator_type"] for m in members}),
            "categories": sorted({m["category"] for m in members}),
            "campaign_ids": sorted({m["campaign_id"] for m in members if m.get("campaign_id")}),
            "first_seen": min(m["first_seen"] for m in members),
            "last_seen": max(m["last_seen"] for m in members),
            "max_risk": max(risks),
            "avg_confidence": round(sum(confs) / len(confs), 1),
            "link_reasons": sorted(link),
            "strength": "STRONG" if len(link) > 1 else "MODERATE",
            "note": CORRELATION_NOTE,
        })
    clusters.sort(key=lambda c: (-c["max_risk"], -c["size"]))
    for i, c in enumerate(clusters, start=1):
        c["cluster_id"] = f"CLU-{i:03d}"
    return clusters


def _load_records(conn) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT t.threat_id, t.category, t.campaign_id, t.first_seen, t.last_seen, t.risk_score, "
        "t.confidence_score, t.status, i.indicator_value, i.indicator_type FROM threats t "
        "JOIN indicators i ON i.threat_id = t.threat_id AND i.is_primary = 1")]


def get_clusters(conn, min_size: int = 2, limit: int = 50) -> dict:
    clusters = correlate_threats(_load_records(conn), min_size=min_size)
    return {"total_clusters": len(clusters), "clusters": clusters[:limit], "note": CORRELATION_NOTE}


def find_related_threats(conn, threat_id: str, limit: int = 25) -> list[dict]:
    """Records linked to `threat_id` by shared campaign, primary or secondary indicator."""
    rows = conn.execute(
        """
        WITH me AS (SELECT campaign_id FROM threats WHERE threat_id = :tid),
             my_ind AS (SELECT normalized_value FROM indicators WHERE threat_id = :tid)
        SELECT DISTINCT t.threat_id, t.threat_name, t.category, t.severity, t.risk_score, t.confidence_score,
               t.status, pi.indicator_type, pi.indicator_value,
               CASE WHEN t.campaign_id IS NOT NULL AND t.campaign_id = (SELECT campaign_id FROM me)
                    THEN 'shared campaign' ELSE 'shared indicator' END AS relationship
        FROM threats t
        JOIN indicators pi ON pi.threat_id = t.threat_id AND pi.is_primary = 1
        WHERE t.threat_id != :tid AND (
              (t.campaign_id IS NOT NULL AND t.campaign_id = (SELECT campaign_id FROM me))
           OR EXISTS (SELECT 1 FROM indicators x WHERE x.threat_id = t.threat_id
                      AND x.normalized_value IN (SELECT normalized_value FROM my_ind)))
        ORDER BY t.risk_score DESC LIMIT :limit
        """, {"tid": threat_id.upper(), "limit": limit}).fetchall()
    return [dict(r) for r in rows]


def count_correlated(conn, indicator_value: str, campaign_id: str | None, exclude_id: str | None = None) -> int:
    """How many existing records share this indicator or campaign (used as scoring context)."""
    row = conn.execute(
        "SELECT COUNT(DISTINCT t.threat_id) FROM threats t JOIN indicators i ON i.threat_id = t.threat_id "
        "WHERE (i.normalized_value = ? OR (? IS NOT NULL AND t.campaign_id = ?)) AND t.threat_id != ?",
        ((indicator_value or "").lower(), campaign_id, campaign_id, exclude_id or "")).fetchone()
    return row[0]
