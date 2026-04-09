from __future__ import annotations

import hashlib
import json
import mimetypes
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from intel_core import (
    ArtifactRecord,
    Confidence,
    IngestRequest,
    JobRecord,
    PluginExecutionContext,
    PluginManifest,
    PluginResult,
    Provenance,
    SourceRecord,
    record_to_dict,
    stable_record_id,
    utc_now,
)
from intel_storage import ensure_workspace_layout, materialize_raw_content


USER_AGENT = "intel-platform/0.1"


@dataclass(slots=True)
class RemoteSourceSnapshot:
    path: str
    requested_type: str
    recursive: bool
    display_name: str
    media_type: str
    size_bytes: int
    cursor: str
    content_hash: str
    file_rows: tuple[dict[str, object], ...]
    request_url: str
    response_status: int
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: bytes = b""
    reused_hash_count: int = 0
    full_hash_count: int = 0
    changed_file_count: int = 0
    append_only_file_count: int = 0
    removed_file_count: int = 0

    @property
    def file_count(self) -> int:
        return len(self.file_rows)


def _ensure_output_dirs(context: PluginExecutionContext, source_id: str, job_id: str) -> tuple[Path, Path]:
    ensure_workspace_layout(context.output_root)
    intake_dir = context.output_root / "intake" / source_id
    queue_dir = context.output_root / "queues" / "extract"
    job_dir = intake_dir / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    queue_dir.mkdir(parents=True, exist_ok=True)
    return job_dir, queue_dir


def _normalize_source_type(value: str) -> str:
    return str(value or "").strip().lower()


def _normalize_headers(values: object) -> dict[str, str]:
    if not isinstance(values, dict):
        return {}
    rows: dict[str, str] = {}
    for key, value in values.items():
        normalized_key = str(key or "").strip()
        normalized_value = str(value or "").strip()
        if not normalized_key or not normalized_value:
            continue
        rows[normalized_key] = normalized_value
    return rows


def _response_headers(headers: object) -> dict[str, str]:
    rows: dict[str, str] = {}
    if hasattr(headers, "items"):
        for key, value in headers.items():
            normalized_key = str(key or "").strip().lower()
            normalized_value = str(value or "").strip()
            if not normalized_key or not normalized_value:
                continue
            rows[normalized_key] = normalized_value
    return rows


def _remote_media_type(url: str, content_type: str, *, default: str = "application/octet-stream") -> str:
    normalized = str(content_type or "").strip().lower()
    if normalized:
        return normalized.split(";", 1)[0].strip() or default
    guessed, _encoding = mimetypes.guess_type(urlparse(url).path)
    return guessed or default


def _content_hash(payload: bytes) -> str:
    return hashlib.sha256(bytes(payload or b"")).hexdigest()


def _cursor_payload(url: str, content_hash: str, status_code: int, headers: dict[str, str]) -> str:
    encoded = json.dumps(
        {
            "url": url,
            "content_hash": content_hash,
            "status_code": int(status_code),
            "etag": str(headers.get("etag") or ""),
            "last_modified": str(headers.get("last-modified") or ""),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _http_error_message(url: str, exc: Exception) -> str:
    if isinstance(exc, HTTPError):
        return f"http request failed for {url}: {exc.code} {exc.reason}"
    if isinstance(exc, URLError):
        return f"http request failed for {url}: {exc.reason}"
    return f"http request failed for {url}: {exc}"


def _response_name(url: str, media_type: str, fallback: str) -> str:
    parsed = urlparse(url)
    name = Path(parsed.path).name
    if name:
        return name
    if media_type.endswith("/json") or media_type.endswith("+json"):
        return f"{fallback}.json"
    if media_type.startswith("text/"):
        return f"{fallback}.txt"
    return f"{fallback}.bin"


def _previous_file_row(previous_watcher_state: dict[str, object] | None) -> dict[str, object]:
    rows = list((previous_watcher_state or {}).get("file_rows") or [])
    for item in rows:
        if isinstance(item, dict):
            return dict(item)
    return {}


def _domain_label(locator: str) -> str:
    return str(locator or "").strip().lower().rstrip(".")


class _RemoteConnectorBase:
    manifest: PluginManifest
    artifact_type: str = "public_source"
    accepted_source_types: tuple[str, ...] = ()
    default_media_type: str = "application/octet-stream"

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def _accepts(self, source_type: str) -> bool:
        return _normalize_source_type(source_type) in self.accepted_source_types

    def _build_url(self, request: IngestRequest) -> str:
        raise NotImplementedError

    def _display_name(self, request: IngestRequest, url: str) -> str:
        return str(request.display_name or url).strip()

    def _artifact_tags(self, request: IngestRequest, url: str) -> tuple[str, ...]:
        parsed = urlparse(url)
        host = str(parsed.netloc or "").strip().lower()
        tags = ["artifact", "ingested", "public-source", "remote"]
        if host:
            tags.append(host)
        return tuple(tags)

    def _request_headers(
        self,
        request: IngestRequest,
        previous_watcher_state: dict[str, object] | None,
    ) -> dict[str, str]:
        _unused = previous_watcher_state
        headers = {
            "User-Agent": USER_AGENT,
            **_normalize_headers(request.options.get("headers")),
        }
        accept = str(request.options.get("accept") or "").strip()
        if accept:
            headers["Accept"] = accept
        return headers

    def _timeout_seconds(self, request: IngestRequest) -> float:
        try:
            return max(1.0, float(request.options.get("timeout_seconds") or 15.0))
        except (TypeError, ValueError):
            return 15.0

    def snapshot_source(
        self,
        request: IngestRequest,
        *,
        previous_watcher_state: dict[str, object] | None = None,
    ) -> RemoteSourceSnapshot:
        requested_type = _normalize_source_type(request.source_type)
        if not self._accepts(requested_type):
            raise ValueError(f"{self.manifest.name} does not accept source type {requested_type!r}")

        url = self._build_url(request)
        previous = dict(previous_watcher_state or {})
        previous_hash = str(previous.get("content_hash") or "").strip().lower()
        previous_row = _previous_file_row(previous)
        request_headers = self._request_headers(request, previous)
        previous_etag = str(previous.get("etag") or previous.get("response_etag") or "").strip()
        previous_last_modified = str(previous.get("last_modified") or previous.get("response_last_modified") or "").strip()
        if previous_etag:
            request_headers.setdefault("If-None-Match", previous_etag)
        if previous_last_modified:
            request_headers.setdefault("If-Modified-Since", previous_last_modified)

        raw_request = Request(url, headers=request_headers, method="GET")
        try:
            with urlopen(raw_request, timeout=self._timeout_seconds(request)) as response:  # noqa: S310 - runtime connector
                body = response.read()
                status_code = int(getattr(response, "status", response.getcode() or 200))
                headers = _response_headers(response.headers)
        except HTTPError as exc:
            if exc.code == 304 and previous_hash:
                headers = _response_headers(exc.headers)
                media_type = str(previous.get("media_type") or previous_row.get("media_type") or self.default_media_type)
                relative_path = str(previous_row.get("relative_path") or _response_name(url, media_type, self.manifest.name))
                size_bytes = int(previous.get("size_bytes") or previous_row.get("size_bytes") or 0)
                cursor = str(previous.get("cursor") or _cursor_payload(url, previous_hash, exc.code, headers))
                return RemoteSourceSnapshot(
                    path=str(request.locator),
                    requested_type=requested_type,
                    recursive=False,
                    display_name=self._display_name(request, url),
                    media_type=media_type,
                    size_bytes=size_bytes,
                    cursor=cursor,
                    content_hash=previous_hash,
                    file_rows=(
                        {
                            "path": url,
                            "relative_path": relative_path,
                            "sha256": previous_hash,
                            "size_bytes": size_bytes,
                            "media_type": media_type,
                            "mtime_ns": 0,
                            "hash_reused": True,
                            "change_kind": "unchanged",
                            "previous_size_bytes": size_bytes,
                            "previous_mtime_ns": 0,
                            "appended_bytes": 0,
                        },
                    ),
                    request_url=url,
                    response_status=exc.code,
                    response_headers=headers,
                    response_body=b"",
                    reused_hash_count=1,
                    full_hash_count=0,
                    changed_file_count=0,
                    append_only_file_count=0,
                    removed_file_count=0,
                )
            raise ValueError(_http_error_message(url, exc)) from exc
        except OSError as exc:
            raise ValueError(_http_error_message(url, exc)) from exc

        media_type = _remote_media_type(url, headers.get("content-type") or "", default=self.default_media_type)
        response_hash = _content_hash(body)
        relative_path = _response_name(url, media_type, self.manifest.name)
        change_kind = "unchanged" if previous_hash and previous_hash == response_hash else ("modified" if previous_hash else "new")
        size_bytes = len(body)
        return RemoteSourceSnapshot(
            path=str(request.locator),
            requested_type=requested_type,
            recursive=False,
            display_name=self._display_name(request, url),
            media_type=media_type,
            size_bytes=size_bytes,
            cursor=_cursor_payload(url, response_hash, status_code, headers),
            content_hash=response_hash,
            file_rows=(
                {
                    "path": url,
                    "relative_path": relative_path,
                    "sha256": response_hash,
                    "size_bytes": size_bytes,
                    "media_type": media_type,
                    "mtime_ns": 0,
                    "hash_reused": False,
                    "change_kind": change_kind,
                    "previous_size_bytes": int(previous_row.get("size_bytes") or 0),
                    "previous_mtime_ns": 0,
                    "appended_bytes": 0,
                },
            ),
            request_url=url,
            response_status=status_code,
            response_headers=headers,
            response_body=body,
            reused_hash_count=0,
            full_hash_count=1,
            changed_file_count=0 if change_kind == "unchanged" else 1,
            append_only_file_count=0,
            removed_file_count=0,
        )

    def collect_from_snapshot(
        self,
        context: PluginExecutionContext,
        request: IngestRequest,
        snapshot: RemoteSourceSnapshot,
    ) -> PluginResult:
        source_id = stable_record_id(
            "source",
            context.case_id,
            snapshot.requested_type,
            snapshot.path,
            snapshot.content_hash,
        )
        job_id = stable_record_id("job", source_id, "extract", "queued")
        job_dir, queue_dir = _ensure_output_dirs(context, source_id, job_id)

        response_name = str(snapshot.file_rows[0].get("relative_path") or _response_name(snapshot.request_url, snapshot.media_type, self.manifest.name))
        object_path, object_hash = materialize_raw_content(
            context.output_root,
            content=snapshot.response_body,
            content_hash=snapshot.content_hash,
            preferred_name=response_name,
        )

        source_record = SourceRecord(
            id=source_id,
            source_id=source_id,
            case_id=context.case_id,
            source_type=snapshot.requested_type,
            locator=snapshot.path,
            display_name=snapshot.display_name,
            collector=self.manifest.name,
            media_type=snapshot.media_type,
            content_hash=snapshot.content_hash,
            size_bytes=snapshot.size_bytes,
            provenance=Provenance(
                plugin=self.manifest.name,
                method="collect",
                source_refs=(snapshot.path, snapshot.request_url),
                notes="ingested by remote connector collector",
            ),
            confidence=Confidence(score=1.0),
            tags=(snapshot.requested_type, "source", "remote-source", "public-source"),
            attributes={
                "request_url": snapshot.request_url,
                "status_code": str(snapshot.response_status),
                "object_store_root": str((context.output_root / "objects" / "raw").resolve()),
                "etag": str(snapshot.response_headers.get("etag") or ""),
                "last_modified": str(snapshot.response_headers.get("last-modified") or ""),
            },
        )

        artifact = ArtifactRecord(
            id=stable_record_id("artifact", source_id, self.artifact_type, object_hash),
            source_id=source_id,
            case_id=context.case_id,
            artifact_type=self.artifact_type,
            path=str(object_path),
            media_type=snapshot.media_type,
            sha256=object_hash,
            size_bytes=snapshot.size_bytes,
            provenance=Provenance(
                plugin=self.manifest.name,
                method="collect",
                source_refs=(source_id,),
                parent_refs=(source_id,),
                notes="remote connector response artifact",
            ),
            confidence=Confidence(score=1.0),
            tags=self._artifact_tags(request, snapshot.request_url),
            attributes={
                "file_name": Path(response_name).name,
                "original_locator": snapshot.path,
                "request_url": snapshot.request_url,
                "status_code": str(snapshot.response_status),
                "etag": str(snapshot.response_headers.get("etag") or ""),
                "last_modified": str(snapshot.response_headers.get("last-modified") or ""),
                "object_path": str(object_path),
            },
        )

        queued_job = JobRecord(
            id=job_id,
            source_id=source_id,
            case_id=context.case_id,
            job_type="pipeline-stage",
            stage="extract",
            status="queued",
            input_refs=(artifact.id,),
            output_refs=(),
            worker=self.manifest.name,
            provenance=Provenance(
                plugin=self.manifest.name,
                method="queue",
                source_refs=(source_id,),
                parent_refs=(source_id,),
                notes="queued extract stage after remote connector ingestion",
            ),
            confidence=Confidence(score=1.0),
            tags=("job", "queued", "extract"),
            attributes={
                "requested_source_type": snapshot.requested_type,
                "artifact_count": "1",
            },
        )

        manifest_payload = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "plugin": {
                "name": self.manifest.name,
                "version": self.manifest.version,
                "type": self.manifest.plugin_type,
            },
            "request": {
                "source_type": snapshot.requested_type,
                "locator": snapshot.path,
                "display_name": snapshot.display_name,
                "options": dict(request.options or {}),
            },
            "source": record_to_dict(source_record),
            "artifacts": [record_to_dict(artifact)],
            "queued_jobs": [record_to_dict(queued_job)],
        }
        manifest_path = job_dir / "source_manifest.json"
        manifest_path.write_text(json.dumps(manifest_payload, indent=2), encoding="utf-8")

        queue_payload = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "job": record_to_dict(queued_job),
            "source": record_to_dict(source_record),
            "artifact_refs": [artifact.id],
            "source_manifest_path": str(manifest_path),
        }
        queue_path = queue_dir / f"{job_id}.json"
        queue_path.write_text(json.dumps(queue_payload, indent=2), encoding="utf-8")

        return PluginResult(
            records=(source_record, artifact, queued_job),
            artifact_paths=(str(manifest_path), str(queue_path)),
            metrics={
                "source_id": source_id,
                "job_id": job_id,
                "file_count": 1,
                "artifact_count": 1,
                "content_hash": snapshot.content_hash,
                "status_code": snapshot.response_status,
                "request_url": snapshot.request_url,
            },
        )

    def collect(self, context: PluginExecutionContext, request: IngestRequest) -> PluginResult:
        try:
            snapshot = self.snapshot_source(request)
        except ValueError as exc:
            return PluginResult(errors=(str(exc),))
        return self.collect_from_snapshot(context, request, snapshot)


class HttpFeedCollectorPlugin(_RemoteConnectorBase):
    manifest = PluginManifest(
        name="http_feed_connector",
        version="0.1.0",
        plugin_type="collector",
        description="Collect approved passive HTTP or HTTPS feeds into source/artifact intake records.",
        capabilities=("http-intake", "public-feed-intake", "source-manifest", "queue-extract-job", "watched-source"),
        input_types=("http-feed", "public-source"),
        output_types=("source", "artifact", "job"),
        policy_tags=("approved-source", "passive-analysis", "public-source"),
        enabled_by_default=True,
    )
    accepted_source_types = ("http-feed", "public-source")
    default_media_type = "application/octet-stream"

    def _build_url(self, request: IngestRequest) -> str:
        url = str(request.locator or request.options.get("url") or "").strip()
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"{self.manifest.name} requires an http or https locator")
        return url

    def _display_name(self, request: IngestRequest, url: str) -> str:
        if request.display_name:
            return str(request.display_name)
        parsed = urlparse(url)
        if parsed.path and parsed.path.strip("/"):
            return str(Path(parsed.path).name or parsed.netloc)
        return str(parsed.netloc or url)

    def _artifact_tags(self, request: IngestRequest, url: str) -> tuple[str, ...]:
        _unused = request
        parsed = urlparse(url)
        tags = ["artifact", "ingested", "public-source", "remote", "http-feed"]
        host = str(parsed.netloc or "").strip().lower()
        if host:
            tags.append(host)
        return tuple(tags)


class RdapDomainCollectorPlugin(_RemoteConnectorBase):
    manifest = PluginManifest(
        name="rdap_domain_connector",
        version="0.1.0",
        plugin_type="collector",
        description="Collect passive RDAP domain records into source/artifact intake records.",
        capabilities=("rdap-domain-intake", "public-domain-intake", "source-manifest", "queue-extract-job", "watched-source"),
        input_types=("domain", "rdap-domain"),
        output_types=("source", "artifact", "job"),
        policy_tags=("approved-source", "passive-analysis", "public-source", "domain-intel"),
        enabled_by_default=True,
    )
    accepted_source_types = ("domain", "rdap-domain")
    default_media_type = "application/rdap+json"

    def _domain(self, request: IngestRequest) -> str:
        domain = _domain_label(str(request.locator or request.options.get("domain") or ""))
        if not domain or "/" in domain or ":" in domain or "." not in domain:
            raise ValueError(f"{self.manifest.name} requires a domain locator like example.com")
        return domain

    def _build_url(self, request: IngestRequest) -> str:
        domain = self._domain(request)
        template = str(
            request.options.get("rdap_base_url")
            or request.options.get("base_url")
            or "https://rdap.org/domain/{domain}"
        ).strip()
        if "{domain}" in template:
            return template.format(domain=quote(domain, safe=""))
        return template.rstrip("/") + "/" + quote(domain, safe="")

    def _display_name(self, request: IngestRequest, url: str) -> str:
        _unused = url
        return str(request.display_name or self._domain(request))

    def _request_headers(
        self,
        request: IngestRequest,
        previous_watcher_state: dict[str, object] | None,
    ) -> dict[str, str]:
        headers = super()._request_headers(request, previous_watcher_state)
        headers.setdefault("Accept", "application/rdap+json, application/json")
        return headers

    def _artifact_tags(self, request: IngestRequest, url: str) -> tuple[str, ...]:
        _unused = url
        domain = self._domain(request)
        return ("artifact", "ingested", "public-source", "remote", "rdap", "domain", domain)


class ApprovedConnectorStubPlugin:
    manifest = PluginManifest(
        name="approved_connector_stub",
        version="0.1.0",
        plugin_type="collector",
        description="Explicit stub surface for unsupported or not-yet-implemented connector collectors.",
        capabilities=("public-source-stub",),
        input_types=("public-source-stub",),
        output_types=("job",),
        policy_tags=("approved-source", "connector-stub"),
        enabled_by_default=False,
    )

    def healthcheck(self) -> tuple[str, ...]:
        return ("connector collection is not implemented yet",)

    def collect(self, context: PluginExecutionContext, request: IngestRequest) -> PluginResult:
        _unused = (context, request)
        return PluginResult(
            errors=("connector collection is not implemented yet for this source type",)
        )
