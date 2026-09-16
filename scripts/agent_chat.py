from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


SERVER_TARGET = os.getenv("KAGOME_SERVER_TARGET", "http://kagome:4000")
PUBLIC_HOST = os.getenv("KAGOME_PUBLIC_HOST", "agent-chat.local:4000")
REDIRECT_URI = os.getenv("KAGOME_REDIRECT_URI", "https://client.example.com/callback")
USERNAME = os.getenv("KAGOME_USERNAME", "username")
PASSWORD = os.getenv("KAGOME_PASSWORD", "password")
TIMEOUT_SECONDS = float(os.getenv("KAGOME_TIMEOUT", "5"))


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, url):
        return None


@dataclass(frozen=True)
class HybridGrant:
    authorization_code: str
    id_token: str
    client_id: str


@dataclass
class Message:
    sender: str
    recipient: str
    content: str


@dataclass
class KagomeClient:
    server_target: str = SERVER_TARGET
    public_host: str = PUBLIC_HOST
    redirect_uri: str = REDIRECT_URI
    username: str = USERNAME
    password: str = PASSWORD
    timeout: float = TIMEOUT_SECONDS

    def hybrid_grant(self) -> HybridGrant:
        public_client_id = f"{self.username}:{self.password}@{self.public_host}"
        query = urlencode(
            {
                "response_type": "code id_token",
                "client_id": public_client_id,
                "redirect_uri": self.redirect_uri,
                "scope": "openid",
            }
        )
        request = Request(
            f"{self.server_target}/authorize?{query}",
            headers={"host": self.public_host},
            method="GET",
        )

        location = self._redirect_location(request, "hybrid authorization")
        parameters = {
            **parse_qs(urlsplit(location).query),
            **parse_qs(urlsplit(location).fragment),
        }
        return HybridGrant(
            authorization_code=first_parameter(parameters, "code"),
            id_token=first_parameter(parameters, "id_token"),
            client_id=f"{self.username}@{self.public_host}",
        )

    def code_chain(
        self,
        grant: HybridGrant,
        previous_authorization_code: str,
    ) -> str:
        body = urlencode(
            {
                "client_id": grant.client_id,
                "grant_type": "code_chain",
                "id_token": grant.id_token,
                "authorization_code": previous_authorization_code,
                "scope": "openid",
            }
        ).encode("utf-8")
        request = Request(
            f"{self.server_target}/token",
            data=body,
            headers={"content-type": "application/x-www-form-urlencoded"},
            method="POST",
        )

        try:
            with build_opener().open(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            response_body = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"code-chain request failed: {error.code} {response_body}"
            ) from error
        except (URLError, TimeoutError, json.JSONDecodeError) as error:
            raise RuntimeError(f"code-chain request failed: {error}") from error

        authorization_code = payload.get("authorization_code")
        if not isinstance(authorization_code, str) or not authorization_code:
            raise RuntimeError("code-chain response has no authorization_code")
        return authorization_code

    def _redirect_location(self, request: Request, operation: str) -> str:
        try:
            build_opener(NoRedirect()).open(request, timeout=self.timeout)
        except HTTPError as error:
            if error.code not in (301, 302, 303, 307, 308):
                body = error.read().decode("utf-8", errors="replace")
                raise RuntimeError(
                    f"{operation} failed: {error.code} {body}"
                ) from error
            location = error.headers.get("location")
            if location:
                return location
            raise RuntimeError(f"{operation} redirect has no location") from error
        except (URLError, TimeoutError) as error:
            raise RuntimeError(f"{operation} failed: {error}") from error

        raise RuntimeError(f"{operation} did not redirect")


@dataclass
class Agent:
    name: str
    handler: Callable[["Agent", list[Message]], Message]
    room: "AgentRoom | None" = None
    inbox: list[Message] = field(default_factory=list)
    authorization_codes: list[str] = field(default_factory=list)

    def receive(self, message: Message, previous_authorization_code: str) -> None:
        if self.room is None:
            raise RuntimeError("agent is not attached to a room")
        authorization_code = self.room.client.code_chain(
            self.room.hybrid_grant,
            previous_authorization_code,
        )
        self.authorization_codes.append(authorization_code)
        self.inbox.append(message)
        print(f"[code_chain -> {self.name}] {short_code(authorization_code)}")

    def respond(self, transcript: list[Message]) -> Message:
        return self.handler(self, transcript)


class AgentRoom:
    def __init__(self, agents: list[Agent], client: KagomeClient) -> None:
        self.agents = {agent.name: agent for agent in agents}
        self.client = client
        self.hybrid_grant = client.hybrid_grant()
        self.transcript: list[Message] = []
        for agent in agents:
            agent.room = self

    def send(self, message: Message) -> None:
        self.transcript.append(message)
        recipient = self.agents.get(message.recipient)
        if recipient is not None:
            recipient.receive(message, self.latest_code(message.sender))

    def latest_code(self, agent_name: str) -> str:
        agent = self.agents.get(agent_name)
        if agent is not None and agent.authorization_codes:
            return agent.authorization_codes[-1]
        return self.hybrid_grant.authorization_code

    def run(self, agent_name: str) -> None:
        self.send(self.agents[agent_name].respond(self.transcript))


def first_parameter(parameters: dict[str, list[str]], name: str) -> str:
    values = parameters.get(name)
    if not values or not values[0]:
        error = parameters.get("error", ["unknown_error"])[0]
        description = parameters.get("error_description", [""])[0]
        raise RuntimeError(
            f"hybrid authorization response has no {name}: {error} {description}".strip()
        )
    return values[0]


def short_code(value: str) -> str:
    return f"{value[:24]}..." if len(value) > 24 else value


def latest(transcript: list[Message], sender: str) -> str:
    for message in reversed(transcript):
        if message.sender == sender:
            return message.content
    return ""


def planner(agent: Agent, transcript: list[Message]) -> Message:
    request = latest(transcript, "user")
    return Message(agent.name, "researcher", f"Plan a concise answer for: {request}")


def researcher(agent: Agent, transcript: list[Message]) -> Message:
    return Message(
        agent.name,
        "critic",
        f"Research result based on this plan: {latest(transcript, 'planner')}",
    )


def critic(agent: Agent, transcript: list[Message]) -> Message:
    return Message(
        agent.name,
        "writer",
        f"Review complete: {latest(transcript, 'researcher')}",
    )


def writer(agent: Agent, transcript: list[Message]) -> Message:
    return Message(
        agent.name,
        "user",
        f"Final answer: {latest(transcript, 'critic')}",
    )


def main() -> None:
    room = AgentRoom(
        [
            Agent("planner", planner),
            Agent("researcher", researcher),
            Agent("critic", critic),
            Agent("writer", writer),
        ],
        KagomeClient(),
    )
    grant = room.hybrid_grant
    print(f"[hybrid client] {grant.client_id}")
    print(f"[hybrid code] {short_code(grant.authorization_code)}")
    print(f"[hybrid id_token] {short_code(grant.id_token)}")

    room.send(Message("user", "planner", "Explain this agent code-chain handoff."))
    for agent_name in ("planner", "researcher", "critic", "writer"):
        room.run(agent_name)

    print("\n[agent chat]")
    for message in room.transcript:
        print(f"{message.sender} -> {message.recipient}: {message.content}")


if __name__ == "__main__":
    main()
