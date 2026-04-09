from __future__ import annotations

from intel_core import (
    ArtifactRecord,
    Confidence,
    EventRecord,
    IdentityRecord,
    IndicatorRecord,
    PluginExecutionContext,
    RelationshipRecord,
)
from intel_correlators import GraphCorrelatorPlugin


def test_graph_correlator_links_identities_domains_urls_and_artifacts() -> None:
    plugin = GraphCorrelatorPlugin()
    records = [
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="file", path="C:/evidence/sample.txt"),
        IndicatorRecord(
            id="indicator-email",
            source_id="source-1",
            indicator_type="email",
            value="alice@example.com",
            normalized_value="alice@example.com",
            confidence=Confidence(score=0.8),
        ),
        IndicatorRecord(
            id="indicator-domain",
            source_id="source-1",
            indicator_type="domain",
            value="example.com",
            normalized_value="example.com",
            confidence=Confidence(score=0.8),
        ),
        IndicatorRecord(
            id="indicator-url",
            source_id="source-1",
            indicator_type="url",
            value="https://example.com/profile",
            normalized_value="https://example.com/profile",
            confidence=Confidence(score=0.8),
        ),
        IdentityRecord(
            id="identity-1",
            source_id="source-1",
            identity_type="email",
            value="alice@example.com",
            normalized_value="alice@example.com",
            attributes={"indicator_id": "indicator-email"},
            confidence=Confidence(score=0.8),
        ),
        RelationshipRecord(
            id="rel-1",
            source_id="source-1",
            relationship_type="artifact_contains_indicator",
            source_ref="artifact-1",
            target_ref="indicator-email",
        ),
        RelationshipRecord(
            id="rel-2",
            source_id="source-1",
            relationship_type="artifact_contains_indicator",
            source_ref="artifact-1",
            target_ref="indicator-domain",
        ),
        RelationshipRecord(
            id="rel-3",
            source_id="source-1",
            relationship_type="artifact_contains_indicator",
            source_ref="artifact-1",
            target_ref="indicator-url",
        ),
        EventRecord(
            id="event-1",
            source_id="source-1",
            event_type="artifact_metadata",
            title="Metadata",
            timestamp="2026-04-08T12:00:00Z",
        ),
    ]

    result = plugin.correlate(PluginExecutionContext(case_id="case-1"), records)

    assert result.ok is True
    relationships = [record for record in result.records if isinstance(record, RelationshipRecord)]
    assert any(record.relationship_type == "identity_uses_domain" for record in relationships)
    assert any(record.relationship_type == "identity_shares_domain_with_url" for record in relationships)
    assert any(record.relationship_type == "artifact_observed_identity" for record in relationships)
    assert any(record.relationship_type == "indicator_cooccurs_with_indicator" for record in relationships)
    assert any(getattr(record, "record_type", "") == "timeline" for record in result.records)


def test_graph_correlator_avoids_duplicate_derived_relationships() -> None:
    plugin = GraphCorrelatorPlugin()
    records = [
        IndicatorRecord(
            id="indicator-email",
            source_id="source-1",
            indicator_type="email",
            value="alice@example.com",
            normalized_value="alice@example.com",
        ),
        IndicatorRecord(
            id="indicator-url",
            source_id="source-1",
            indicator_type="url",
            value="https://example.com/path",
            normalized_value="https://example.com/path",
        ),
        IdentityRecord(
            id="identity-1",
            source_id="source-1",
            identity_type="email",
            value="alice@example.com",
            normalized_value="alice@example.com",
        ),
        RelationshipRecord(
            id="rel-existing",
            source_id="source-1",
            relationship_type="identity_shares_domain_with_url",
            source_ref="identity-1",
            target_ref="indicator-url",
        ),
    ]

    result = plugin.correlate(PluginExecutionContext(case_id="case-1"), records)

    assert result.ok is True
    matching = [
        record
        for record in result.records
        if isinstance(record, RelationshipRecord)
        and record.relationship_type == "identity_shares_domain_with_url"
        and record.source_ref == "identity-1"
        and record.target_ref == "indicator-url"
    ]
    assert len(matching) == 1
