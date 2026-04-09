from __future__ import annotations

from intel_core import (
    Confidence,
    IdentityRecord,
    IndicatorRecord,
    PluginExecutionContext,
    RelationshipRecord,
)
from intel_normalizers import CanonicalRecordNormalizerPlugin


def test_canonical_normalizer_normalizes_and_deduplicates_indicator_values() -> None:
    plugin = CanonicalRecordNormalizerPlugin()
    records = [
        IndicatorRecord(
            id="indicator-1",
            source_id="source-1",
            indicator_type="email",
            value="Alice@Example.com",
            normalized_value="",
            confidence=Confidence(score=0.7),
        ),
        IndicatorRecord(
            id="indicator-2",
            source_id="source-1",
            indicator_type="email",
            value="alice@example.com",
            normalized_value="alice@example.com",
            confidence=Confidence(score=0.7),
        ),
        IndicatorRecord(
            id="indicator-3",
            source_id="source-1",
            indicator_type="url",
            value="HTTPS://Example.com/path#frag",
            normalized_value="",
            confidence=Confidence(score=0.7),
        ),
    ]

    result = plugin.normalize(PluginExecutionContext(case_id="case-1"), records)

    assert result.ok is True
    indicators = [record for record in result.records if isinstance(record, IndicatorRecord)]
    identities = [record for record in result.records if isinstance(record, IdentityRecord)]
    relationships = [record for record in result.records if isinstance(record, RelationshipRecord)]

    assert len(indicators) == 2
    assert any(record.normalized_value == "alice@example.com" for record in indicators)
    assert any(record.normalized_value == "https://example.com/path" for record in indicators)
    assert len(identities) == 1
    assert any(record.relationship_type == "indicator_identifies_identity" for record in relationships)


def test_canonical_normalizer_remaps_relationships_after_dedupe() -> None:
    plugin = CanonicalRecordNormalizerPlugin()
    email_one = IndicatorRecord(
        id="indicator-1",
        source_id="source-1",
        indicator_type="email",
        value="User@Example.com",
    )
    email_two = IndicatorRecord(
        id="indicator-2",
        source_id="source-1",
        indicator_type="email",
        value="user@example.com",
    )
    relationship = RelationshipRecord(
        id="rel-1",
        source_id="source-1",
        relationship_type="artifact_contains_indicator",
        source_ref="artifact-1",
        target_ref="indicator-2",
    )

    result = plugin.normalize(PluginExecutionContext(), [email_one, email_two, relationship])

    assert result.ok is True
    relationships = [record for record in result.records if isinstance(record, RelationshipRecord)]
    assert any(record.target_ref == "indicator-1" for record in relationships)
