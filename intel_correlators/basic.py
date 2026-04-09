from __future__ import annotations

from datetime import datetime
from itertools import combinations
from urllib.parse import urlsplit

from intel_core import (
    ArtifactRecord,
    Confidence,
    EventRecord,
    IdentityRecord,
    IndicatorRecord,
    PluginExecutionContext,
    PluginManifest,
    PluginResult,
    Provenance,
    RecordBase,
    RelationshipRecord,
    TimelineRecord,
    canonical_fingerprint,
    stable_record_id,
)


class GraphCorrelatorPlugin:
    manifest = PluginManifest(
        name="graph_correlator",
        version="0.1.0",
        plugin_type="correlator",
        description="Correlate normalized records into linked relationships, artifact clusters, and source timelines.",
        capabilities=("relationship-correlation", "timeline-correlation", "artifact-clustering"),
        input_types=("record-batch",),
        output_types=("record-batch",),
        policy_tags=("passive-analysis",),
    )

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def correlate(self, context: PluginExecutionContext, records: list[RecordBase] | tuple[RecordBase, ...]) -> PluginResult:
        input_records = list(records)
        artifacts = [record for record in input_records if isinstance(record, ArtifactRecord)]
        indicators = [record for record in input_records if isinstance(record, IndicatorRecord)]
        identities = [record for record in input_records if isinstance(record, IdentityRecord)]
        relationships = [record for record in input_records if isinstance(record, RelationshipRecord)]
        events = [record for record in input_records if isinstance(record, EventRecord)]

        derived_records: list[RecordBase] = []
        derived_records.extend(self._derive_artifact_identity_links(context, artifacts, identities, relationships))
        derived_records.extend(self._derive_domain_links(context, indicators, identities))
        derived_records.extend(self._derive_indicator_cooccurrence(context, relationships))

        timeline = self._build_timeline(context, events, input_records)
        if timeline is not None:
            derived_records.append(timeline)

        deduped_records, duplicate_count = self._dedupe_records(input_records, derived_records)
        summary = EventRecord(
            id=stable_record_id(
                "event",
                next((record.source_id for record in input_records if record.source_id), ""),
                context.case_id,
                "correlation_summary",
            ),
            source_id=next((record.source_id for record in input_records if record.source_id), ""),
            case_id=context.case_id,
            event_type="correlation_summary",
            title="Correlation summary",
            summary="Correlated normalized records into linked relationships, artifact context, and timeline output.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="correlate",
                notes="Correlation stage summary",
            ),
            confidence=Confidence(score=0.9),
            tags=("correlate", "summary"),
            attributes={
                "input_count": str(len(input_records)),
                "derived_count": str(len(deduped_records)),
                "duplicate_count": str(duplicate_count),
                "timeline_count": str(sum(1 for record in deduped_records if isinstance(record, TimelineRecord))),
                "relationship_count": str(sum(1 for record in deduped_records if isinstance(record, RelationshipRecord))),
            },
        )

        return PluginResult(
            records=(*input_records, *deduped_records, summary),
            metrics={
                "derived_count": len(deduped_records),
                "duplicate_count": duplicate_count,
                "timeline_count": sum(1 for record in deduped_records if isinstance(record, TimelineRecord)),
                "relationship_count": sum(1 for record in deduped_records if isinstance(record, RelationshipRecord)),
            },
        )

    def _derive_artifact_identity_links(
        self,
        context: PluginExecutionContext,
        artifacts: list[ArtifactRecord],
        identities: list[IdentityRecord],
        relationships: list[RelationshipRecord],
    ) -> list[RelationshipRecord]:
        _unused = artifacts
        indicator_to_artifacts: dict[str, set[str]] = {}
        for record in relationships:
            if record.relationship_type != "artifact_contains_indicator":
                continue
            indicator_to_artifacts.setdefault(record.target_ref, set()).add(record.source_ref)

        derived: list[RelationshipRecord] = []
        for identity in identities:
            indicator_id = identity.attributes.get("indicator_id", "").strip()
            if not indicator_id:
                continue
            artifact_ids = sorted(indicator_to_artifacts.get(indicator_id, set()))
            for artifact_id in artifact_ids:
                derived.append(
                    RelationshipRecord(
                        id=stable_record_id(
                            "relationship",
                            artifact_id,
                            identity.id,
                            "artifact_observed_identity",
                        ),
                        source_id=identity.source_id,
                        case_id=context.case_id or identity.case_id,
                        relationship_type="artifact_observed_identity",
                        source_ref=artifact_id,
                        target_ref=identity.id,
                        reason="correlator linked an identity back to the artifact where its indicator was observed",
                        provenance=Provenance(
                            plugin=self.manifest.name,
                            method="artifact-indicator-identity",
                            source_refs=(identity.source_id,),
                            parent_refs=(artifact_id, indicator_id, identity.id),
                        ),
                        confidence=Confidence(score=0.86),
                        tags=("correlate", "artifact", "identity"),
                    )
                )
        return derived

    def _derive_domain_links(
        self,
        context: PluginExecutionContext,
        indicators: list[IndicatorRecord],
        identities: list[IdentityRecord],
    ) -> list[RelationshipRecord]:
        domain_indicators: dict[str, list[IndicatorRecord]] = {}
        url_indicators_by_host: dict[str, list[IndicatorRecord]] = {}
        for indicator in indicators:
            normalized = str(indicator.normalized_value or indicator.value).strip().lower()
            if indicator.indicator_type == "domain" and normalized:
                domain_indicators.setdefault(normalized, []).append(indicator)
            elif indicator.indicator_type == "url":
                host = self._url_host(normalized or indicator.value)
                if host:
                    url_indicators_by_host.setdefault(host, []).append(indicator)

        derived: list[RelationshipRecord] = []
        for identity in identities:
            if identity.identity_type != "email":
                continue
            domain = self._email_domain(identity.normalized_value or identity.value)
            if not domain:
                continue

            for indicator in domain_indicators.get(domain, []):
                derived.append(
                    RelationshipRecord(
                        id=stable_record_id(
                            "relationship",
                            identity.id,
                            indicator.id,
                            "identity_uses_domain",
                        ),
                        source_id=identity.source_id,
                        case_id=context.case_id or identity.case_id,
                        relationship_type="identity_uses_domain",
                        source_ref=identity.id,
                        target_ref=indicator.id,
                        reason="correlator matched an email identity to a normalized domain indicator",
                        provenance=Provenance(
                            plugin=self.manifest.name,
                            method="email-domain-match",
                            source_refs=(identity.source_id,),
                            parent_refs=(identity.id, indicator.id),
                        ),
                        confidence=Confidence(score=0.9),
                        tags=("correlate", "identity", "domain"),
                    )
                )

            for indicator in url_indicators_by_host.get(domain, []):
                derived.append(
                    RelationshipRecord(
                        id=stable_record_id(
                            "relationship",
                            identity.id,
                            indicator.id,
                            "identity_shares_domain_with_url",
                        ),
                        source_id=identity.source_id,
                        case_id=context.case_id or identity.case_id,
                        relationship_type="identity_shares_domain_with_url",
                        source_ref=identity.id,
                        target_ref=indicator.id,
                        reason="correlator matched an email identity domain to a URL host",
                        provenance=Provenance(
                            plugin=self.manifest.name,
                            method="email-url-domain-match",
                            source_refs=(identity.source_id,),
                            parent_refs=(identity.id, indicator.id),
                        ),
                        confidence=Confidence(score=0.85),
                        tags=("correlate", "identity", "url"),
                    )
                )

        for domain, url_indicators in url_indicators_by_host.items():
            for url_indicator in url_indicators:
                for domain_indicator in domain_indicators.get(domain, []):
                    derived.append(
                        RelationshipRecord(
                            id=stable_record_id(
                                "relationship",
                                url_indicator.id,
                                domain_indicator.id,
                                "url_references_domain",
                            ),
                            source_id=url_indicator.source_id,
                            case_id=context.case_id or url_indicator.case_id,
                            relationship_type="url_references_domain",
                            source_ref=url_indicator.id,
                            target_ref=domain_indicator.id,
                            reason="correlator matched a URL host to a normalized domain indicator",
                            provenance=Provenance(
                                plugin=self.manifest.name,
                                method="url-domain-match",
                                source_refs=(url_indicator.source_id,),
                                parent_refs=(url_indicator.id, domain_indicator.id),
                            ),
                            confidence=Confidence(score=0.88),
                            tags=("correlate", "url", "domain"),
                        )
                    )
        return derived

    def _derive_indicator_cooccurrence(
        self,
        context: PluginExecutionContext,
        relationships: list[RelationshipRecord],
    ) -> list[RelationshipRecord]:
        artifact_to_indicators: dict[str, set[str]] = {}
        for record in relationships:
            if record.relationship_type != "artifact_contains_indicator":
                continue
            artifact_to_indicators.setdefault(record.source_ref, set()).add(record.target_ref)

        derived: list[RelationshipRecord] = []
        for artifact_id, indicator_ids in artifact_to_indicators.items():
            ordered = sorted(indicator_ids)
            for left_id, right_id in combinations(ordered, 2):
                derived.append(
                    RelationshipRecord(
                        id=stable_record_id(
                            "relationship",
                            left_id,
                            right_id,
                            "indicator_cooccurs_with_indicator",
                        ),
                        source_id="",
                        case_id=context.case_id,
                        relationship_type="indicator_cooccurs_with_indicator",
                        source_ref=left_id,
                        target_ref=right_id,
                        directed=False,
                        reason=f"correlator observed both indicators in artifact {artifact_id}",
                        provenance=Provenance(
                            plugin=self.manifest.name,
                            method="artifact-cooccurrence",
                            parent_refs=(artifact_id, left_id, right_id),
                        ),
                        confidence=Confidence(score=0.78),
                        tags=("correlate", "indicator", "cooccurrence"),
                    )
                )
        return derived

    def _build_timeline(
        self,
        context: PluginExecutionContext,
        events: list[EventRecord],
        records: list[RecordBase],
    ) -> TimelineRecord | None:
        ordered = []
        for event in events:
            timestamp = self._event_time_value(event)
            if not timestamp:
                continue
            ordered.append((timestamp, event))

        if not ordered:
            return None

        ordered.sort(key=lambda item: item[0])
        source_id = next((record.source_id for record in records if record.source_id), "")
        start_time = ordered[0][0]
        end_time = ordered[-1][0]
        return TimelineRecord(
            id=stable_record_id("timeline", source_id, context.case_id, tuple(event.id for _, event in ordered)),
            source_id=source_id,
            case_id=context.case_id,
            title=f"Timeline for {source_id or context.case_id or 'source'}",
            start_time=start_time,
            end_time=end_time,
            event_refs=tuple(event.id for _, event in ordered),
            summary=f"Ordered {len(ordered)} events between {start_time} and {end_time}.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="event-sort",
                source_refs=(source_id,) if source_id else (),
                parent_refs=tuple(event.id for _, event in ordered),
            ),
            confidence=Confidence(score=0.87),
            tags=("correlate", "timeline"),
            attributes={"event_count": str(len(ordered))},
        )

    def _dedupe_records(
        self,
        input_records: list[RecordBase],
        derived_records: list[RecordBase],
    ) -> tuple[list[RecordBase], int]:
        seen = {canonical_fingerprint(record) for record in input_records}
        deduped: list[RecordBase] = []
        duplicate_count = 0
        for record in derived_records:
            fingerprint = canonical_fingerprint(record)
            if fingerprint in seen:
                duplicate_count += 1
                continue
            seen.add(fingerprint)
            deduped.append(record)
        return deduped, duplicate_count

    def _email_domain(self, value: str) -> str:
        text = str(value or "").strip().lower()
        if "@" not in text:
            return ""
        return text.rsplit("@", 1)[1].rstrip(".")

    def _url_host(self, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        try:
            split = urlsplit(text)
        except ValueError:
            return ""
        return str(split.hostname or "").strip().lower().rstrip(".")

    def _event_time_value(self, event: EventRecord) -> str:
        for candidate in (event.timestamp, event.observed_at, event.created_at):
            normalized = self._normalize_timestamp(candidate)
            if normalized:
                return normalized
        return ""

    def _normalize_timestamp(self, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        iso_value = text[:-1] + "+00:00" if text.endswith("Z") else text
        try:
            parsed = datetime.fromisoformat(iso_value)
        except ValueError:
            return ""
        return parsed.isoformat().replace("+00:00", "Z")
