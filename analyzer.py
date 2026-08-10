"""Core log parsing and anomaly detection for SignalScope."""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime

LINE = re.compile(r"^(?P<time>\S+)\s+(?P<level>DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL)\s+(?P<service>[\w.-]+)\s*[-:]\s*(?P<message>.+)$", re.I)
VARIABLE = re.compile(r"(?:\d+(?:\.\d+)?(?:ms|s|mb|gb|%)?|[0-9a-f]{8,}|[\w.+-]+@[\w.-]+|/[^\s]+)", re.I)
WEIGHT = {"DEBUG": 0, "INFO": 1, "WARN": 3, "WARNING": 3, "ERROR": 7, "CRITICAL": 10}


@dataclass
class Event:
    timestamp: str
    level: str
    service: str
    message: str
    fingerprint: str


def fingerprint(message: str) -> str:
    normalized = VARIABLE.sub("<?>" , message.lower())
    return hashlib.sha1(normalized.encode()).hexdigest()[:10]


def parse(text: str) -> tuple[list[Event], int]:
    events, rejected = [], 0
    for raw in text.splitlines():
        if not raw.strip():
            continue
        match = LINE.match(raw.strip())
        if not match:
            rejected += 1
            continue
        data = match.groupdict()
        level = data["level"].upper().replace("WARNING", "WARN")
        try:
            stamp = datetime.fromisoformat(data["time"].replace("Z", "+00:00")).isoformat()
        except ValueError:
            rejected += 1
            continue
        events.append(Event(stamp, level, data["service"], data["message"], fingerprint(data["message"])))
    return events, rejected


def analyze(events: list[Event]) -> dict:
    if not events:
        return {"total": 0, "health": 100, "critical": 0, "services": [], "groups": [], "timeline": [], "summary": "No valid events were found."}
    by_service, by_group, timeline = defaultdict(list), defaultdict(list), Counter()
    for event in events:
        by_service[event.service].append(event)
        by_group[event.fingerprint].append(event)
        timeline[event.timestamp[:16]] += 1
    services = []
    for name, items in by_service.items():
        risk = sum(WEIGHT[x.level] for x in items)
        services.append({"name": name, "events": len(items), "errors": sum(x.level in {"ERROR", "CRITICAL"} for x in items), "risk": min(100, round(risk / len(items) * 10))})
    services.sort(key=lambda x: x["risk"], reverse=True)
    groups = []
    for fp, items in by_group.items():
        severity = max(WEIGHT[x.level] for x in items)
        score = min(100, round(severity * 7 + math.log2(len(items) + 1) * 10))
        groups.append({"fingerprint": fp, "message": items[0].message, "service": items[0].service, "level": max(items, key=lambda x: WEIGHT[x.level]).level, "count": len(items), "score": score, "first": min(x.timestamp for x in items), "last": max(x.timestamp for x in items)})
    groups.sort(key=lambda x: (x["score"], x["count"]), reverse=True)
    critical = sum(x.level in {"ERROR", "CRITICAL"} for x in events)
    health = max(0, 100 - round(sum(WEIGHT[x.level] for x in events) / len(events) * 7))
    top = groups[0]
    summary = f"{critical} high-severity events across {len(by_service)} services. Primary signal: {top['service']} produced “{top['message']}” {top['count']} time(s). Investigate this service first."
    return {"total": len(events), "health": health, "critical": critical, "services": services, "groups": groups[:12], "timeline": [{"time": k, "count": v} for k, v in sorted(timeline.items())], "summary": summary}
