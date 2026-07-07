"""AgentBus — async pubsub for multi-agent communication.

Specialists publish observations to topics. Other specialists subscribe
to topics they care about. The orchestrator monitors all traffic.

Topics:
  - "finding:new"     — a new vulnerability finding
  - "finding:validated" — finding passed 7-Question Gate
  - "tool:start" / "tool:done" — tool execution lifecycle
  - "phase:enter" / "phase:exit" — phase transitions
  - "stuck"           — an agent is stuck, needs operator help
  - "complete"        — an agent completed its subtask
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable


@dataclass
class BusMessage:
    """A message on the AgentBus."""
    topic: str
    sender: str                    # agent name
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "topic": self.topic,
            "sender": self.sender,
            "data": self.data,
            "timestamp": self.timestamp,
        }


class AgentBus:
    """In-process pubsub message bus for multi-agent communication.

    Each agent has a mailbox (list of messages). Agents can publish
    to topics and subscribe to topics they're interested in.
    """

    def __init__(self, max_history: int = 1000):
        self._subscriptions: dict[str, set[str]] = defaultdict(set)  # topic → {agent_names}
        self._mailboxes: dict[str, list[BusMessage]] = defaultdict(list)
        self._history: list[BusMessage] = []
        self._max_history = max_history
        self._callbacks: dict[str, list[Callable]] = defaultdict(list)

    # ── Subscribe / Unsubscribe ───────────────────────────────────

    def subscribe(self, agent_name: str, topic: str) -> None:
        """Subscribe an agent to a topic."""
        self._subscriptions[topic].add(agent_name)

    def unsubscribe(self, agent_name: str, topic: str) -> None:
        self._subscriptions[topic].discard(agent_name)

    def on(self, topic: str, callback: Callable) -> None:
        """Register a callback for a topic. Callback receives BusMessage."""
        self._callbacks[topic].append(callback)

    # ── Publish ───────────────────────────────────────────────────

    def publish(self, topic: str, sender: str, data: dict[str, Any] | None = None) -> None:
        """Publish a message to a topic."""
        msg = BusMessage(topic=topic, sender=sender, data=data or {})

        # Store in history
        self._history.append(msg)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        # Deliver to subscribers' mailboxes
        for agent_name in self._subscriptions.get(topic, set()):
            self._mailboxes[agent_name].append(msg)

        # Fire callbacks
        for cb in self._callbacks.get(topic, []):
            try:
                cb(msg)
            except Exception:
                pass

    # ── Mailbox ───────────────────────────────────────────────────

    def receive(self, agent_name: str, topic: str | None = None,
                max_messages: int = 20) -> list[BusMessage]:
        """Get messages for an agent, optionally filtered by topic.

        Messages are consumed (removed from mailbox).
        """
        mailbox = self._mailboxes[agent_name]
        if topic:
            matching = [m for m in mailbox if m.topic == topic]
            remaining = [m for m in mailbox if m.topic != topic]
            self._mailboxes[agent_name] = remaining
            return matching[:max_messages]
        else:
            result = mailbox[:max_messages]
            self._mailboxes[agent_name] = mailbox[max_messages:]
            return result

    def peek(self, agent_name: str) -> list[BusMessage]:
        """View messages without consuming them."""
        return list(self._mailboxes[agent_name])

    # ── Query ─────────────────────────────────────────────────────

    def history(self, topic: str | None = None, limit: int = 50) -> list[BusMessage]:
        """Get recent message history, optionally filtered by topic."""
        if topic:
            return [m for m in self._history if m.topic == topic][-limit:]
        return self._history[-limit:]

    @property
    def subscriber_count(self) -> int:
        return sum(len(agents) for agents in self._subscriptions.values())
