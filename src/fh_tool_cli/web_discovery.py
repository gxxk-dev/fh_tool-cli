from __future__ import annotations

import json
import re
from collections import deque
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse

import requests

from .backends.web_ajax import DEFAULT_AJAX_PATH, WEB_TYPED_METHODS, redact_web_payload

DEFAULT_MAX_RESOURCES = 200
DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024

READ_PREFIXES = ("get_", "query_", "show_")
WRITE_PREFIXES = ("set_", "add_", "del_", "delete_", "apply_", "save_", "modify_")
AUTH_METHODS = {"web_get_brmad", "get_operator", "do_login", "get_login_user"}
KNOWN_WRITE_METHODS = {"setVlanBind"}
KNOWN_READ_METHODS = {method for method in WEB_TYPED_METHODS.values()}

IGNORED_RESOURCE_EXTENSIONS = {
    ".bmp",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".png",
    ".svg",
    ".webp",
    ".eot",
    ".otf",
    ".ttf",
    ".woff",
    ".woff2",
    ".avi",
    ".mp4",
    ".mpeg",
    ".mpg",
    ".webm",
    ".zip",
    ".gz",
    ".tgz",
    ".tar",
    ".rar",
    ".7z",
}

TEXT_RESOURCE_EXTENSIONS = {".", ".asp", ".css", ".htm", ".html", ".js", ".json", ".shtml", ".txt", ".xml"}

METHOD_RE = re.compile(
    r"\b(?:get|set|add|del|delete|query|show|apply|save|modify)_[A-Za-z0-9_]+\b|"
    r"\b(?:setVlanBind|vlanbind|web_get_brmad|do_login|get_operator|get_login_user)\b"
)
AJAXMETHOD_RE = re.compile(r"\bajaxmethod\b\s*[:=]\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
AJAX_QUERY_RE = re.compile(r"[?&]ajaxmethod=([^&'\"<>\s)]+)", re.IGNORECASE)
DATA_OBJECT_RE = re.compile(r"\bdata\s*:\s*\{(?P<body>.*?)\}", re.IGNORECASE | re.DOTALL)
PARAM_ASSIGN_RE = re.compile(r"\b[A-Za-z_$][\w$]*\s*\[\s*['\"]([^'\"]+)['\"]\s*\]")
HTML_NAME_RE = re.compile(r"\b(?:input|select|textarea)\b[^>]*\bname\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
LINK_RE = re.compile(
    r"""(?:href|src|action)\s*=\s*['"]([^'"]+)['"]|url\(\s*['"]?([^'")]+)['"]?\s*\)""",
    re.IGNORECASE,
)

SENSITIVE_PARAM_RE = re.compile(
    r"(sessionid|token|password|passwd|pwd|loginpd|loid|pppoe|acs|secret|psk|wepkey|wpakey)",
    re.IGNORECASE,
)


def classify_method(method: str) -> str:
    if method in AUTH_METHODS:
        return "auth"
    if method in KNOWN_WRITE_METHODS or method.startswith(WRITE_PREFIXES):
        return "write"
    if method in KNOWN_READ_METHODS or method.startswith(READ_PREFIXES):
        return "read"
    return "unknown"


def sensitive_name(name: str) -> bool:
    return bool(SENSITIVE_PARAM_RE.search(name))


def empty_catalog(
    *,
    base_url: str | None = None,
    ajax_path: str = DEFAULT_AJAX_PATH,
    discovery_mode: str | None = None,
    auth: dict[str, Any] | None = None,
) -> dict[str, Any]:
    catalog: dict[str, Any] = {
        "target": {
            "base_url": base_url,
            "ajax_path": ajax_path,
        },
        "auth": auth or {},
        "methods": [],
        "skipped_resources": [],
    }
    if discovery_mode:
        catalog["discovery"] = {"mode": discovery_mode}
    return catalog


def method_entry(
    method: str,
    *,
    http_method: str = "GET",
    source: str | None = None,
    params: list[str] | None = None,
    context: str | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "method": method,
        "http_methods": [http_method.upper()],
        "kind": classify_method(method),
        "sources": [source] if source else [],
        "params": [_param_entry(name) for name in params or [] if name != "ajaxmethod"],
        "verified": False,
    }
    verify = verify_candidates_for(method)
    if verify:
        entry["verify_candidates"] = verify
    if context:
        entry["contexts"] = [{"source": source, "snippet": context}]
    return entry


def verify_candidates_for(method: str) -> list[str]:
    if method in {"set_wan_info", "add_wan_info", "delete_wan_info", "modify_wan_info"}:
        return ["get_allwan_info"]
    if method == "set_port_mapping_info":
        return ["get_port_mapping_info"]
    if method == "setVlanBind":
        return ["vlanbind"]
    if method == "set_services":
        return ["get_services"]
    if method == "set_firewall_info":
        return ["get_firewall_info"]
    return []


def extract_ajax_entries(text: str, source: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()

    for match in AJAXMETHOD_RE.finditer(text):
        method = match.group(1)
        context = _snippet(text, match.start(), match.end())
        params = extract_params_from_context(context, include_query=False)
        http_method = _infer_http_method(context, method)
        _append_entry(entries, seen, method, http_method, source, params, context)

    for match in AJAX_QUERY_RE.finditer(text):
        method = match.group(1)
        context = _snippet(text, match.start(), match.end())
        params = _params_from_query_context(context)
        _append_entry(entries, seen, method, "GET", source, params, context)

    for match in METHOD_RE.finditer(text):
        method = match.group(0)
        context = _snippet(text, match.start(), match.end())
        params = extract_params_from_context(context, include_query=False)
        http_method = _infer_http_method(context, method)
        _append_entry(entries, seen, method, http_method, source, params, context)

    if "form.serialize" in text or ".serialize()" in text:
        names = _unique(HTML_NAME_RE.findall(text))
        for entry in entries:
            _merge_params_into_entry(entry, names)

    return entries


def extract_params_from_context(context: str, *, include_query: bool = True) -> list[str]:
    params: list[str] = []
    for match in DATA_OBJECT_RE.finditer(context):
        params.extend(_object_literal_keys(match.group("body")))
    params.extend(PARAM_ASSIGN_RE.findall(context))
    params.extend(HTML_NAME_RE.findall(context))
    if include_query:
        params.extend(_params_from_query_context(context))
    return _unique(name for name in params if name != "ajaxmethod")


def static_catalog(root: Path, *, ajax_path: str = DEFAULT_AJAX_PATH) -> dict[str, Any]:
    root = root.expanduser()
    catalog = empty_catalog(ajax_path=ajax_path, discovery_mode="static")
    entries: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for path in _static_resource_paths(root):
        try:
            stat = path.stat()
        except OSError as exc:
            skipped.append({"path": str(path), "reason": f"stat: {exc}"})
            continue
        if stat.st_size > DEFAULT_MAX_FILE_SIZE:
            skipped.append({"path": str(path), "reason": "too_large", "bytes": stat.st_size})
            continue
        if _ignored_extension(path.name):
            skipped.append({"path": str(path), "reason": "ignored_extension"})
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            skipped.append({"path": str(path), "reason": f"read: {exc}"})
            continue
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        entries.extend(extract_ajax_entries(text, rel))
    merged = merge_catalogs(
        [
            {
                **catalog,
                "methods": entries,
                "skipped_resources": skipped,
            }
        ]
    )
    merged["discovery"] = {"mode": "static", "root": str(root)}
    return merged


def crawl_same_origin_resources(
    session: Any,
    base_url: str,
    *,
    timeout: float,
    max_resources: int = DEFAULT_MAX_RESOURCES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> dict[str, Any]:
    visited: set[str] = set()
    resources: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    queue: deque[tuple[str, int]] = deque([(base_url, 0)])

    while queue and len(visited) < max_resources:
        url, depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        if not _same_origin(base_url, url):
            skipped.append({"url": url, "reason": "cross_origin"})
            continue
        if _ignored_extension(urlparse(url).path):
            skipped.append({"url": url, "reason": "ignored_extension"})
            continue
        try:
            response = session.get(url, timeout=timeout, allow_redirects=False)
        except requests.RequestException as exc:
            skipped.append({"url": url, "reason": f"request: {exc}"})
            continue
        content_type = response.headers.get("Content-Type")
        size = _response_size(response)
        resource = {
            "url": url,
            "depth": depth,
            "status_code": response.status_code,
            "content_type": content_type,
            "bytes": size,
        }
        resources.append(resource)
        if size > max_file_size:
            skipped.append({"url": url, "reason": "too_large", "bytes": size})
            continue
        if response.status_code >= 400 or not _looks_textual(url, content_type):
            continue
        text = response.text
        entries.extend(extract_ajax_entries(text, url))
        if depth >= max_depth:
            continue
        for link in _extract_links(text, url):
            if not _same_origin(base_url, link):
                skipped.append({"url": link, "reason": "cross_origin"})
                continue
            if _ignored_extension(urlparse(link).path):
                skipped.append({"url": link, "reason": "ignored_extension"})
                continue
            if link not in visited and len(visited) + len(queue) < max_resources:
                queue.append((link, depth + 1))

    if queue:
        skipped.append({"url": "*", "reason": "max_resources", "limit": max_resources})
    return {
        "resources": resources,
        "skipped_resources": skipped,
        "methods": entries,
    }


def probe_read_methods(
    client: Any,
    catalog: dict[str, Any],
    *,
    save_samples: bool = False,
) -> dict[str, Any]:
    probed: list[dict[str, Any]] = []
    by_method = {entry.get("method"): entry for entry in catalog.get("methods", []) if isinstance(entry, dict)}
    for method, entry in sorted(by_method.items()):
        if not isinstance(method, str) or entry.get("kind") != "read":
            continue
        try:
            result = client.ajax_get(method)
        except Exception as exc:  # noqa: BLE001 - discovery records per-method failures.
            entry["verified"] = False
            entry["probe_error"] = str(exc)
            probed.append({"method": method, "ok": False, "error": str(exc)})
            continue
        entry["verified"] = bool(result.get("ok"))
        entry["status_code"] = result.get("status_code")
        entry["content_type"] = result.get("content_type")
        entry["sessionid_present"] = bool(result.get("sessionid_present"))
        response = result.get("response")
        entry["response_shape"] = response_shape(response)
        if save_samples and response is not None:
            entry["sample"] = redact_web_payload(response)
        probed.append({"method": method, "ok": bool(result.get("ok")), "status_code": result.get("status_code")})
    catalog["probe"] = {"read_methods": probed}
    return catalog


def response_shape(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {
            "type": "object",
            "top_level_keys": sorted(str(key) for key in value.keys()),
        }
    if isinstance(value, list):
        shape: dict[str, Any] = {"type": "array", "length": len(value)}
        if value:
            shape["item"] = response_shape(value[0])
        return shape
    if value is None:
        return {"type": "null"}
    return {"type": type(value).__name__}


def merge_catalogs(catalogs: list[dict[str, Any]]) -> dict[str, Any]:
    first_ajax_path = _first_catalog_value(catalogs, "ajax_path")
    merged = empty_catalog(ajax_path=first_ajax_path or DEFAULT_AJAX_PATH)
    merged["skipped_resources"] = []
    merged["resources"] = []
    entries_by_method: dict[str, dict[str, Any]] = {}

    for catalog in catalogs:
        _merge_target(merged, catalog)
        if catalog.get("auth"):
            merged["auth"] = {**merged.get("auth", {}), **catalog["auth"]}
        if catalog.get("discovery"):
            merged.setdefault("discovery", {}).update(catalog["discovery"])
        merged["skipped_resources"].extend(catalog.get("skipped_resources", []))
        merged["resources"].extend(catalog.get("resources", []))
        for entry in catalog.get("methods", []):
            if not isinstance(entry, dict) or not entry.get("method"):
                continue
            method = str(entry["method"])
            if method not in entries_by_method:
                entries_by_method[method] = _normalize_entry(entry)
                continue
            _merge_entry(entries_by_method[method], entry)

    merged["methods"] = sorted(entries_by_method.values(), key=lambda item: item["method"])
    if not merged["skipped_resources"]:
        merged.pop("skipped_resources", None)
    if not merged["resources"]:
        merged.pop("resources", None)
    return merged


def find_catalog_method(catalog: dict[str, Any], method: str) -> dict[str, Any]:
    for entry in catalog.get("methods", []):
        if isinstance(entry, dict) and entry.get("method") == method:
            return entry
    raise KeyError(method)


def read_catalog(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"catalog 读取失败: {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("methods"), list):
        raise ValueError("catalog 必须是包含 methods list 的 JSON object")
    return data


def write_catalog(catalog: dict[str, Any], output: Path | None) -> dict[str, Any]:
    if output is None:
        return catalog
    output = output.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"output": str(output), "methods": len(catalog.get("methods", []))}


def _append_entry(
    entries: list[dict[str, Any]],
    seen: set[tuple[str, str, tuple[str, ...]]],
    method: str,
    http_method: str,
    source: str,
    params: list[str],
    context: str,
) -> None:
    method = method.strip()
    if not method:
        return
    key = (method, http_method.upper(), tuple(params))
    if key in seen:
        return
    seen.add(key)
    entries.append(
        method_entry(
            method,
            http_method=http_method,
            source=source,
            params=params,
            context=context,
        )
    )


def _infer_http_method(context: str, method: str) -> str:
    if classify_method(method) == "write":
        return "POST"
    if re.search(r"\btype\s*:\s*['\"]POST['\"]|\bmethod\s*:\s*['\"]POST['\"]", context, re.IGNORECASE):
        return "POST"
    return "GET"


def _params_from_query_context(context: str) -> list[str]:
    params: list[str] = []
    for marker in ("?", "&"):
        if f"{marker}ajaxmethod=" not in context:
            continue
        for query in re.findall(r"\?([^'\"<>\s)]+)", context):
            params.extend(name for name, _value in parse_qsl(query, keep_blank_values=True))
    return _unique(name for name in params if name != "ajaxmethod")


def _object_literal_keys(body: str) -> list[str]:
    keys: list[str] = []
    for match in re.finditer(r"(?:^|[,{\s])['\"]?([A-Za-z_][\w.-]*)['\"]?\s*:", body):
        keys.append(match.group(1))
    return _unique(keys)


def _param_entry(name: str) -> dict[str, Any]:
    return {"name": name, "sensitive": sensitive_name(name)}


def _merge_params_into_entry(entry: dict[str, Any], names: list[str]) -> None:
    existing = {param.get("name") for param in entry.get("params", []) if isinstance(param, dict)}
    for name in names:
        if name == "ajaxmethod" or name in existing:
            continue
        entry.setdefault("params", []).append(_param_entry(name))
        existing.add(name)


def _snippet(text: str, start: int, end: int, *, radius: int = 220) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    snippet = re.sub(r"\s+", " ", text[left:right]).strip()
    return _redact_context_snippet(snippet[:500])


def _redact_context_snippet(snippet: str) -> str:
    sensitive = r"(?:sessionid|token|password|passwd|pwd|loginpd|loid|pppoe|acs|secret|psk|wepkey|wpakey)"
    snippet = re.sub(
        rf"([?&]{sensitive}=)[^&'\"<>\s)]+",
        r"\1[REDACTED]",
        snippet,
        flags=re.IGNORECASE,
    )
    snippet = re.sub(
        rf"(\b{sensitive}\b\s*[:=]\s*['\"])[^'\"]*(['\"])",
        r"\1[REDACTED]\2",
        snippet,
        flags=re.IGNORECASE,
    )
    return re.sub(
        rf"(\b{sensitive}\b\s*[:=]\s*)[^,\s&'\"}})]+",
        r"\1[REDACTED]",
        snippet,
        flags=re.IGNORECASE,
    )


def _unique(values: Any) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        value = value.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _static_resource_paths(root: Path) -> list[Path]:
    candidates = [
        root,
        root / "www",
        root / "web",
        root / "fhrom",
        root / "cgi-bin",
        root / "usr" / "www",
        root / "home" / "httpd",
    ]
    paths: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if not candidate.exists():
            continue
        iterable = candidate.rglob("*") if candidate.is_dir() else [candidate]
        for path in iterable:
            if not path.is_file() or path in seen:
                continue
            seen.add(path)
            if _looks_static_text_file(path):
                paths.append(path)
    return paths


def _looks_static_text_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in IGNORED_RESOURCE_EXTENSIONS:
        return False
    if suffix in TEXT_RESOURCE_EXTENSIONS:
        return True
    return suffix == "" or path.name in {"config", "index"}


def _ignored_extension(path_or_name: str) -> bool:
    return Path(urlparse(path_or_name).path).suffix.lower() in IGNORED_RESOURCE_EXTENSIONS


def _same_origin(base_url: str, url: str) -> bool:
    base = urlparse(base_url)
    other = urlparse(url)
    return (base.scheme, base.hostname, base.port) == (other.scheme, other.hostname, other.port)


def _response_size(response: Any) -> int:
    length = response.headers.get("Content-Length")
    if length and str(length).isdigit():
        return int(length)
    return len(response.content)


def _looks_textual(url: str, content_type: str | None) -> bool:
    if content_type:
        lowered = content_type.lower()
        if any(marker in lowered for marker in ("text/", "javascript", "json", "xml", "html", "css")):
            return True
    suffix = Path(urlparse(url).path).suffix.lower()
    return suffix in TEXT_RESOURCE_EXTENSIONS or suffix == ""


def _extract_links(text: str, base_url: str) -> list[str]:
    links: list[str] = []
    for match in LINK_RE.finditer(text):
        raw = match.group(1) or match.group(2)
        if not raw:
            continue
        if raw.startswith(("javascript:", "mailto:", "#", "data:")):
            continue
        absolute = urljoin(base_url, raw)
        links.append(absolute)
    return _unique(links)


def _merge_target(target: dict[str, Any], catalog: dict[str, Any]) -> None:
    source_target = catalog.get("target")
    if not isinstance(source_target, dict):
        return
    merged_target = target.setdefault("target", {})
    for key, value in source_target.items():
        if not value:
            continue
        if not merged_target.get(key) or (key == "ajax_path" and merged_target.get(key) == DEFAULT_AJAX_PATH):
            merged_target[key] = value


def _first_catalog_value(catalogs: list[dict[str, Any]], key: str) -> Any:
    for catalog in catalogs:
        target = catalog.get("target")
        if isinstance(target, dict) and target.get(key):
            return target[key]
    return None


def _normalize_entry(entry: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "method": str(entry["method"]),
        "http_methods": sorted({str(item).upper() for item in entry.get("http_methods", ["GET"])}),
        "kind": entry.get("kind") or classify_method(str(entry["method"])),
        "sources": _unique(entry.get("sources", [])),
        "params": [],
        "verified": bool(entry.get("verified", False)),
    }
    for param in entry.get("params", []):
        if isinstance(param, dict) and param.get("name"):
            _merge_params_into_entry(normalized, [str(param["name"])])
    for key in (
        "status_code",
        "content_type",
        "sessionid_present",
        "response_shape",
        "sample",
        "probe_error",
        "verify_candidates",
        "contexts",
    ):
        if key in entry:
            normalized[key] = entry[key]
    return normalized


def _merge_entry(base: dict[str, Any], incoming: dict[str, Any]) -> None:
    base["http_methods"] = sorted(
        {*(str(item).upper() for item in base.get("http_methods", [])), *(str(item).upper() for item in incoming.get("http_methods", []))}
    )
    base["sources"] = _unique([*base.get("sources", []), *incoming.get("sources", [])])
    incoming_params = [
        str(param["name"])
        for param in incoming.get("params", [])
        if isinstance(param, dict) and param.get("name")
    ]
    _merge_params_into_entry(base, incoming_params)
    base["verified"] = bool(base.get("verified")) or bool(incoming.get("verified"))
    if incoming.get("kind") == "write" or base.get("kind") == "unknown":
        base["kind"] = incoming.get("kind") or base.get("kind")
    for key in ("verify_candidates", "contexts"):
        if key in incoming:
            base[key] = _merge_list_of_values(base.get(key, []), incoming.get(key, []))
    for key in ("status_code", "content_type", "sessionid_present", "response_shape", "sample", "probe_error"):
        if key in incoming and (incoming.get("verified") or key not in base):
            base[key] = incoming[key]


def _merge_list_of_values(left: Any, right: Any) -> list[Any]:
    result: list[Any] = []
    seen: set[str] = set()
    for value in [*(left if isinstance(left, list) else []), *(right if isinstance(right, list) else [])]:
        marker = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(value)
    return result


def make_ajax_query(method: str, params: dict[str, Any] | None = None) -> str:
    request_params = {"ajaxmethod": method}
    if params:
        request_params.update(params)
    return f"{DEFAULT_AJAX_PATH}?{urlencode(request_params)}"
