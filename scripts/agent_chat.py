from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


CLIENT_ID = os.getenv("KAGOME_CLIENT_ID", "client_id")
CLIENT_SECRET = os.getenv("KAGOME_CLIENT_SECRET", "client_secret")
TOKEN_TARGET = os.getenv("KAGOME_TOKEN_TARGET", "http://127.0.0.1:4000/token")
TOKEN_TIMEOUT_SECONDS = float(os.getenv("KAGOME_TOKEN_TIMEOUT", "5"))


@dataclass
class Message:
    sender: str
    recipient: str
    content: str


@dataclass(frozen=True)
class AgentKeyPair:
    key_id: str
    secret: bytes

    def id_token(self) -> str:
        now = int(time.time())
        header = {
            "alg": "HS256",
            "typ": "JWT",
            "kid": self.key_id,
            "jwk": {
                "kty": "oct",
                "k": base64_url(self.secret),
                "alg": "HS256",
                "kid": self.key_id,
            },
        }
        payload = {
            "iat": now,
            "exp": now + 3600,
        }
        signing_input = f"{base64_url_json(header)}.{base64_url_json(payload)}"
        signature = hmac.new(
            self.secret,
            signing_input.encode("ascii"),
            hashlib.sha256,
        ).digest()

        return f"{signing_input}.{base64_url(signature)}"


@dataclass
class CodeChainTokenClient:
    token_target: str = TOKEN_TARGET
    client_id: str = CLIENT_ID
    client_secret: str = CLIENT_SECRET
    timeout: float = TOKEN_TIMEOUT_SECONDS

    def issue_authorization_code(
        self,
        key_pair: AgentKeyPair,
        previous_authorization_code: str | None = None,
    ) -> str:
        parameters = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "code_chain",
            "id_token": key_pair.id_token(),
        }
        if previous_authorization_code is not None:
            parameters["authorization_code"] = previous_authorization_code

        request_body = urlencode(parameters).encode("utf-8")
        request = Request(
            self.token_target,
            data=request_body,
            headers={"content-type": "application/x-www-form-urlencoded"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"code_chain token call failed for {key_pair.key_id}: {error} {body}"
            ) from error
        except (URLError, TimeoutError, json.JSONDecodeError) as error:
            raise RuntimeError(
                f"code_chain token call failed for {key_pair.key_id}: {error}"
            ) from error

        authorization_code = payload.get("authorization_code")
        if not isinstance(authorization_code, str) or not authorization_code:
            raise RuntimeError(
                f"code_chain token response missing authorization_code for {key_pair.key_id}"
            )

        return authorization_code


@dataclass
class Agent:
    name: str
    instructions: str
    handler: Callable[["Agent", list[Message]], Message]
    key_pair: AgentKeyPair
    token_client: CodeChainTokenClient
    inbox: list[Message] = field(default_factory=list)
    authorization_codes: list[str] = field(default_factory=list)

    def receive(
        self,
        message: Message,
        previous_authorization_code: str | None = None,
    ) -> None:
        authorization_code = self.token_client.issue_authorization_code(
            self.key_pair,
            previous_authorization_code,
        )
        self.authorization_codes.append(authorization_code)
        print(f"[code_chain -> {self.name}]")
        print(authorization_code)
        self.inbox.append(message)

    def respond(self, transcript: list[Message]) -> Message:
        return self.handler(self, transcript)


class AgentRoom:
    def __init__(self, agents: list[Agent]) -> None:
        self.agents = {agent.name: agent for agent in agents}
        self.transcript: list[Message] = []

    def send(self, message: Message) -> None:
        self.transcript.append(message)
        if message.recipient in self.agents:
            self.agents[message.recipient].receive(
                message,
                self.latest_authorization_code(message.sender),
            )

    def ask(self, sender: str, recipient: str, content: str) -> None:
        self.send(Message(sender=sender, recipient=recipient, content=content))

    def run_round(self, agent_name: str) -> Message:
        message = self.agents[agent_name].respond(self.transcript)
        self.send(message)
        return message

    def latest_authorization_code(self, agent_name: str) -> str | None:
        agent = self.agents.get(agent_name)
        if agent is None or not agent.authorization_codes:
            return None

        return agent.authorization_codes[-1]

    def print_transcript(self) -> None:
        for message in self.transcript:
            print(f"\n[{message.sender} -> {message.recipient}]")
            print(message.content)


def latest_user_request(transcript: list[Message]) -> str:
    for message in reversed(transcript):
        if message.sender == "user":
            return message.content
    return ""


def latest_from(transcript: list[Message], sender: str) -> str:
    for message in reversed(transcript):
        if message.sender == sender:
            return message.content
    return ""


def local_writer_reply(request: str, plan: str, critique: str) -> str:
    return (
        f"Final response for: {request}\n\n"
        "A planner agent turned the request into a concrete plan, a critic agent "
        "checked that plan for gaps, and this writer agent produced the final "
        "reply from those intermediate results.\n\n"
        f"Planner output:\n{plan}\n\n"
        f"Critic output:\n{critique}"
    )


def base64_url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def base64_url_json(value: object) -> str:
    return base64_url(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def agent_key_pair(agent_name: str) -> AgentKeyPair:
    return AgentKeyPair(
        key_id=f"{agent_name}-key",
        secret=f"{agent_name}-agent-code-chain-secret".encode("utf-8"),
    )


def agent(
    name: str,
    instructions: str,
    handler: Callable[[Agent, list[Message]], Message],
    token_client: CodeChainTokenClient,
) -> Agent:
    return Agent(
        name=name,
        instructions=instructions,
        handler=handler,
        key_pair=agent_key_pair(name),
        token_client=token_client,
    )


def planner_handler(agent: Agent, transcript: list[Message]) -> Message:
    request = latest_user_request(transcript)
    plan = (
        f"Goal: {request}\n"
        "Plan:\n"
        "1. Identify the user's concrete outcome.\n"
        "2. Split the work into small steps.\n"
        "3. Draft a direct answer with a runnable example.\n"
        "4. Ask the critic to check for missing assumptions."
    )
    return Message(sender=agent.name, recipient="critic", content=plan)


def critic_handler(agent: Agent, transcript: list[Message]) -> Message:
    plan = latest_from(transcript, "planner")
    critique = (
        "Review:\n"
        "- The plan is clear, but the final answer should avoid abstract theory.\n"
        "- Include the exact command to run the example.\n"
        "- Show where each agent contributes so the interaction is visible.\n\n"
        f"Plan reviewed:\n{plan}"
    )
    return Message(sender=agent.name, recipient="writer", content=critique)


def writer_handler(agent: Agent, transcript: list[Message]) -> Message:
    request = latest_user_request(transcript)
    plan = latest_from(transcript, "planner")
    critique = latest_from(transcript, "critic")
    answer = local_writer_reply(request, plan, critique)
    return Message(sender=agent.name, recipient="user", content=answer)


def main() -> None:
    token_client = CodeChainTokenClient()
    room = AgentRoom(
        agents=[
            agent(
                name="planner",
                instructions="Break a user request into a practical plan.",
                handler=planner_handler,
                token_client=token_client,
            ),
            agent(
                name="critic",
                instructions="Find gaps and risks in another agent's plan.",
                handler=critic_handler,
                token_client=token_client,
            ),
            agent(
                name="writer",
                instructions="Write the final user-facing answer.",
                handler=writer_handler,
                token_client=token_client,
            ),
        ]
    )

    user_prompt = "Test agentic code-chain workflow."
    print(
        """
+--------------------------+
| Agentic Code-Chain Test |
+--------------------------+
""".strip()
    )

    room.ask("user", "planner", user_prompt)
    room.run_round("planner")
    room.run_round("critic")
    room.run_round("writer")
    room.print_transcript()


if __name__ == "__main__":
    main()
