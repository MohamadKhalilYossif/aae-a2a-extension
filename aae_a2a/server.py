"""Supplier agent: an A2A server that declares the AAE extension in its Agent
Card and verifies an AAE before it performs a gated skill.

Profile mapping (spec sections 5-8):
  message 1  SendMessage with metadata[URI] = {"aae", "ancestor_jws"?} and one
             data Part {"skill", "transaction"}  ->  section 5 steps 1-3, then
             Task in TASK_STATE_AUTH_REQUIRED carrying the step-4 challenge
  message 2  SendMessage on that task with metadata[URI] = {"challenge_response"}
             ->  section 5 steps 1-9. Accepted: the skill runs and the task ends in
             its outcome, TASK_STATE_COMPLETED or TASK_STATE_FAILED, with the
             ACCEPT receipt in Task.metadata[URI] either way. Rejected:
             TASK_STATE_REJECTED with the failing step, and the skill never runs.
             Both results carry request_digest (spec section 8.5).
Protocol violations (extension not activated, metadata missing) are JSON-RPC
errors and create no task.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from google.protobuf import json_format
from starlette.applications import Starlette

from a2a.extensions.common import find_extension_by_uri
from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.context import ServerCallContext
from a2a.server.events.event_queue import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.server.tasks.task_updater import TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentExtension,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    Message,
    Part,
    SendMessageRequest,
    Task,
    TaskState,
    TaskStatus,
)
from a2a.utils.errors import ExtensionSupportRequiredError, InvalidParamsError

from .challenge import ChallengeError, SubjectBinding, utc_now
from .constants import A2A_EXTENSIONS_HEADER, AAE_DRAFT, EXTENSION_URI, MAX_ANCESTORS
from .didres import LocalDidResolver
from .digest import request_bytes, request_digest
from . import enforce
from .verifier import STEP_NAMES, AaeVerifier, Accepted, Reject

log = logging.getLogger("aae_a2a.supplier")

RPC_PATH = "/a2a/jsonrpc"


# --- request decoding ------------------------------------------------------------

def normalize_numbers(v):
    """google.protobuf.Value carries every number as a double. Map integral
    doubles within +/-2^53 back to integers (spec section 6.3)."""
    if isinstance(v, float) and v.is_integer() and abs(v) <= 2 ** 53:
        return int(v)
    if isinstance(v, dict):
        return {k: normalize_numbers(x) for k, x in v.items()}
    if isinstance(v, list):
        return [normalize_numbers(x) for x in v]
    return v


def extension_metadata(message: Message) -> object:
    md = json_format.MessageToDict(message.metadata) if message.HasField("metadata") else {}
    return md.get(EXTENSION_URI)


def request_part(message: Message) -> dict | None:
    """The single data Part {"skill", "transaction"} of an AAE-gated request."""
    data_parts = [p for p in message.parts if p.WhichOneof("content") == "data"]
    if len(data_parts) != 1:
        return None
    data = normalize_numbers(json_format.MessageToDict(data_parts[0].data))
    if not isinstance(data, dict) or set(data) != {"skill", "transaction"}:
        return None
    if not isinstance(data["skill"], str) or not isinstance(data["transaction"], dict):
        return None
    return data


def _invalid(reason_code: str, message: str) -> InvalidParamsError:
    # error.data becomes google.rpc.ErrorInfo.metadata, whose values are strings.
    return InvalidParamsError(message=message,
                              data={"extension": EXTENSION_URI, "reason_code": reason_code})


# --- configuration -----------------------------------------------------------------

@dataclass
class ProfileConfig:
    audience: str
    skills: dict[str, dict]
    accepted_issuers: list[str] | None
    did_methods: list[str]
    required: bool = True
    own_aae: str | None = None
    deferred_decisions: bool = False

    def params(self) -> dict:
        p = {
            "draft": AAE_DRAFT,
            "audience": self.audience,
            "skills": self.skills,
            "did_methods": self.did_methods,
            "max_ancestors": MAX_ANCESTORS,
        }
        if self.accepted_issuers is not None:
            p["accepted_issuers"] = self.accepted_issuers
        if self.own_aae:
            p["own_aae"] = {"jws": self.own_aae}
        if self.deferred_decisions:
            p["deferred_decisions"] = True
        return p


def build_agent_card(base_url: str, cfg: ProfileConfig) -> AgentCard:
    ext = AgentExtension(
        uri=EXTENSION_URI,
        description=("Requests to gated skills must carry an AAE (Agent Authorization Envelope, "
                     f"{AAE_DRAFT}) issued to the calling agent; it is verified per section 5 "
                     "before the task proceeds."),
        required=cfg.required,
    )
    ext.params.update(cfg.params())
    return AgentCard(
        name="Example Supplier Agent",
        description="Accepts quotes and purchase orders from buyer agents that present an AAE.",
        version="1.0.0",
        provider=AgentProvider(organization="Example Supplier Co", url="https://supplier.example"),
        capabilities=AgentCapabilities(streaming=False, push_notifications=False, extensions=[ext]),
        default_input_modes=["application/json", "text/plain"],
        default_output_modes=["application/json", "text/plain"],
        skills=[
            AgentSkill(id="get-quote", name="Get quote", tags=["procurement"],
                       description="Price a list of items. AAE action: read."),
            AgentSkill(id="place-order", name="Place order", tags=["procurement"],
                       description="Place a purchase order. AAE action: pay."),
        ],
        supported_interfaces=[AgentInterface(protocol_binding="JSONRPC", protocol_version="1.0",
                                             url=base_url.rstrip("/") + RPC_PATH)],
    )


# --- request handler: protocol-level checks ---------------------------------------

class AaeRequestHandler(DefaultRequestHandler):
    """Adds the profile's protocol checks in front of the SDK handler (spec 8.1)."""

    def __init__(self, *args, required: bool, is_held=lambda _task_id: False, **kwargs):
        super().__init__(*args, **kwargs)
        self._required = required
        self._is_held = is_held

    async def on_message_send(self, params: SendMessageRequest, context: ServerCallContext):
        activated = EXTENSION_URI in context.requested_extensions
        if not activated:
            if self._required:
                raise ExtensionSupportRequiredError(
                    message=f"Extension {EXTENSION_URI} is required and was not activated",
                    data={"extension": EXTENSION_URI})
            return await super().on_message_send(params, context)
        md = extension_metadata(params.message)
        if params.message.task_id and self._is_held(params.message.task_id):
            rat = md.get("ratification") if isinstance(md, dict) else None
            if not isinstance(rat, dict) or rat.get("decision") not in (enforce.APPROVED,
                                                                        enforce.DISAPPROVED):
                raise _invalid("ratification_malformed",
                               f"metadata[{EXTENSION_URI}].ratification with decision APPROVED "
                               "or DISAPPROVED is required for a held task (spec 7.6)")
            if request_part(params.message) is not None:
                raise _invalid("ratification_malformed",
                               "a ratification message carries no request part (spec 7.6)")
        elif params.message.task_id:
            if not isinstance(md, dict) or not isinstance(md.get("challenge_response"), str):
                raise _invalid("challenge_response_missing",
                               f"metadata[{EXTENSION_URI}].challenge_response is required")
        else:
            if not isinstance(md, dict) or not isinstance(md.get("aae"), str):
                raise _invalid("aae_missing", f"metadata[{EXTENSION_URI}].aae is required")
            # Shape only. The count bound is applied in step 9 and reported as a
            # rejection, not a transport error (AAE -02 sections 5 step 9, 7.9).
            anc = md.get("ancestor_jws", [])
            if not isinstance(anc, list) or not all(isinstance(a, str) for a in anc):
                raise _invalid("ancestor_jws_invalid", "ancestor_jws must be an array of strings")
            if request_part(params.message) is None:
                raise _invalid("request_part_invalid",
                               'exactly one data Part {"skill", "transaction"} is required')
        return await super().on_message_send(params, context)


# --- executor: AAE verification and the skill itself -------------------------------

class SkillFailed(Exception):
    """The skill ran and did not succeed. The authorization decision stands."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# What the example supplier stocks. An order for anything else is accepted by
# the AAE check and then fails in the skill: the paired case of section 8.3.
CATALOGUE = frozenset({"PAPER-A4", "TONER-K1"})


def perform_skill(skill: str, tx: dict) -> dict:
    if skill == "place-order":
        unknown = sorted({i.get("sku") for i in tx.get("items", []) if isinstance(i, dict)}
                         - CATALOGUE, key=str)
        if unknown:
            raise SkillFailed(f"not in catalogue: {', '.join(map(str, unknown))}")
        return {"order_id": "PO-0001", "status": "confirmed",
                "amount": tx.get("amount"), "currency": tx.get("currency"),
                "items": tx.get("items", [])}
    return {"quote": {"items": tx.get("items", []), "valid_minutes": 30}}


@dataclass
class _Pending:
    aae: str
    ancestor_jws: list
    skill: str
    transaction: dict
    aae_id: str
    nonce: str
    request_digest: str


class HandoffMismatch(Exception):
    """A decision was handed to a task it was not made for. Raised before the
    skill runs and before the task changes state."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class Decision:
    """The accepted outcome of section 5 for one task and one frozen request.

    The verifier-to-executor handoff passes this object and nothing else that
    describes the request: the skill is invoked with the request decoded from
    request_bytes, never with a request taken from the receiving context. A
    decision is bound to the task it was verified on; _dispatch refuses it on
    any other task (spec 8.5: request_digest identifies content, the task id
    the execution)."""
    task_id: str
    skill: str
    action: str
    request_digest: str
    request_bytes: bytes
    accepted: Accepted
    verified_at: object

    @classmethod
    def bind(cls, task_id: str, p: "_Pending", accepted: Accepted, now, action: str) -> "Decision":
        raw = request_bytes({"skill": p.skill, "transaction": p.transaction})
        if "sha256:" + hashlib.sha256(raw).hexdigest() != p.request_digest:
            raise HandoffMismatch("request_not_frozen",
                                  "the pending request no longer matches its frozen digest")
        return cls(task_id=task_id, skill=p.skill, action=action,
                   request_digest=p.request_digest, request_bytes=raw,
                   accepted=accepted, verified_at=now)

    def frozen_request(self) -> dict:
        if "sha256:" + hashlib.sha256(self.request_bytes).hexdigest() != self.request_digest:
            raise HandoffMismatch("request_not_frozen", self.request_digest)
        return json.loads(self.request_bytes)


@dataclass
class _Held:
    pending: _Pending
    vc: dict
    root_vc: dict
    enforce_result: dict
    steps: list
    hold_result: dict


@dataclass
class SupplierExecutor(AgentExecutor):
    cfg: ProfileConfig
    verifier: AaeVerifier
    binding: SubjectBinding
    clock: callable = utc_now
    perform: callable = perform_skill
    # Called as observer(task_id, result, task_state_name) for every decision;
    # the cross-run server uses it to log what it decided (CROSSRUN.md).
    observer: callable = None
    pending: dict[str, _Pending] = field(default_factory=dict)
    # Tasks held under PENDING until a ratification closes them (spec 7.6).
    held: dict[str, _Held] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def is_held(self, task_id: str) -> bool:
        with self.lock:
            return task_id in self.held

    @property
    def rp_domain(self) -> str:
        return urlsplit(self.cfg.audience).hostname or ""

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        with self.lock:
            self.pending.pop(context.task_id or "", None)
        await TaskUpdater(event_queue, context.task_id or "", context.context_id or "").cancel()

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        task_id, context_id, msg = context.task_id, context.context_id, context.message
        updater = TaskUpdater(event_queue, task_id, context_id)
        if context.current_task is None:
            await event_queue.enqueue_event(Task(
                id=task_id, context_id=context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED), history=[msg]))
            await self._first_message(context, updater)
        else:
            with self.lock:
                held = self.held.get(task_id)
            if held is not None:
                await self._ratification(context, updater, held)
                return
            with self.lock:
                pending = self.pending.pop(task_id, None)
            if pending is None or context.current_task.status.state != TaskState.TASK_STATE_AUTH_REQUIRED:
                await self._reject(updater, Reject(0, "no_pending_challenge",
                                                   "this task has no outstanding AAE challenge"))
                return
            await self._challenge_response(context, updater, pending)

    async def _first_message(self, context: RequestContext, updater: TaskUpdater) -> None:
        msg = context.message
        if EXTENSION_URI not in context.requested_extensions:
            req = request_part(msg)
            await self._reject(updater, Reject(0, "extension_not_activated"),
                               request_digest(req) if req is not None else None)
            return
        md = extension_metadata(msg)
        req = request_part(msg)
        # Frozen here: the challenge response cannot change the request (6.3),
        # so this digest is the one every result on this task reports.
        digest = request_digest(req)
        skill = self.cfg.skills.get(req["skill"])
        if skill is None:
            await self._reject(updater, Reject(0, "skill_not_gated", req["skill"]), digest)
            return
        now = self.clock()
        try:
            vc = self.verifier.precheck(md["aae"], now)
        except Reject as r:
            await self._reject(updater, r, digest)
            return
        nonce = self.binding.mint(self.cfg.audience, vc["id"], now)
        with self.lock:
            self.pending[context.task_id] = _Pending(
                aae=md["aae"], ancestor_jws=md.get("ancestor_jws", []), skill=req["skill"],
                transaction=req["transaction"], aae_id=vc["id"], nonce=nonce,
                request_digest=digest)
        challenge = {"nonce": nonce, "aud": self.cfg.audience, "aae_id": vc["id"]}
        status_msg = updater.new_agent_message(parts=[Part(
            text="AAE steps 1-3 passed. Prove control of credentialSubject.id: return a JWS "
                 "over {nonce, aud, iat, aae_id} signed with an authentication key of that DID.")])
        status_msg.metadata.update({EXTENSION_URI: {"challenge": challenge}})
        status_msg.extensions.append(EXTENSION_URI)
        await updater.requires_auth(message=status_msg)

    async def _challenge_response(self, context: RequestContext, updater: TaskUpdater,
                                  p: _Pending) -> None:
        md = extension_metadata(context.message)
        response = md.get("challenge_response") if isinstance(md, dict) else None
        if EXTENSION_URI not in context.requested_extensions or not isinstance(response, str):
            await self._reject(updater, Reject(4, "challenge_response_missing"),
                               p.request_digest)
            return
        now = self.clock()
        action = self.cfg.skills[p.skill]["action"]
        tx = p.transaction

        def subject_binding(vc: dict) -> None:
            try:
                self.binding.verify_response(
                    response, subject_did=vc["credentialSubject"]["id"], aae_id=vc["id"],
                    aud=self.cfg.audience, expected_nonce=p.nonce, now=now)
            except ChallengeError as exc:
                raise Reject(4, exc.reason.split(":")[0], exc.reason) from exc

        try:
            accepted = self.verifier.verify(
                p.aae, now=now, action=action, subject_binding=subject_binding,
                ancestor_jws=p.ancestor_jws, transaction=tx,
                hold_pending=self.cfg.deferred_decisions,
                action_ctx={"amount": tx.get("amount"), "currency": tx.get("currency"),
                            "domain": self.rp_domain})
        except Reject as r:
            await self._reject(updater, r, p.request_digest)
            return
        if accepted.held:
            await self._hold(updater, p, accepted)
            return
        await self._dispatch(updater, Decision.bind(updater.task_id, p, accepted, now, action))

    async def _dispatch(self, updater: TaskUpdater, decision: Decision,
                        ratification: dict | None = None) -> None:
        """The verifier-to-executor handoff. Everything the skill receives comes
        from the decision; the receiving context contributes only where the
        outcome is reported, and it must be the task the decision was made on."""
        if updater.task_id != decision.task_id:
            raise HandoffMismatch("decision_task_mismatch",
                                  f"decision for task {decision.task_id} handed to {updater.task_id}")
        req = decision.frozen_request()
        accepted, now, action = decision.accepted, decision.verified_at, decision.action
        tx = req["transaction"]
        receipt = {
            "verdict": "ACCEPT",
            "draft": AAE_DRAFT,
            "steps_passed": accepted.steps,
            "aae_id": accepted.vc["id"],
            "issuer": accepted.root_vc["issuer"],
            "subject": accepted.vc["credentialSubject"]["id"],
            "skill": req["skill"],
            "action": action,
            "verified_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "request_digest": decision.request_digest,
        }
        if accepted.enforce_result is not None:
            receipt["enforce"] = _enforce_view(accepted.enforce_result)
        if ratification is not None:
            receipt["ratification"] = ratification
        # The receipt records the decision and is in place before the skill runs.
        # What the skill then does is the task's terminal state, not the receipt.
        await updater.update_status(TaskState.TASK_STATE_WORKING,
                                    metadata={EXTENSION_URI: {"result": receipt}})
        try:
            output = self.perform(req["skill"], tx)
        except SkillFailed as exc:
            self._observe(updater, receipt, TaskState.TASK_STATE_FAILED)
            await updater.failed(message=updater.new_agent_message(parts=[Part(
                text=f"{req['skill']} failed: {exc.reason}. AAE {accepted.vc['id']} was verified; "
                     "the failure is the skill's, not the authorization's.")]))
            return
        await updater.add_artifact(parts=[Part(data=_to_value(output))],
                                   name="result", last_chunk=True)
        self._observe(updater, receipt, TaskState.TASK_STATE_COMPLETED)
        await updater.complete(message=updater.new_agent_message(
            parts=[Part(text=f"{req['skill']} done; AAE {accepted.vc['id']} verified.")]))

    async def _hold(self, updater: TaskUpdater, p: _Pending, accepted) -> None:
        """PENDING at step 6, every other step passed: hold the task (spec 7.6)."""
        mandate = accepted.vc["credentialSubject"]["aae"]["mandate"]
        result = {
            "verdict": "PENDING",
            "draft": AAE_DRAFT,
            "steps_passed": accepted.steps,
            "enforce": _enforce_view(accepted.enforce_result),
            "authorities": [did for did, _k, _r in enforce.mandate_authorities(mandate)],
            "aae_id": accepted.vc["id"],
            "request_digest": p.request_digest,
        }
        with self.lock:
            self.held[updater.task_id] = _Held(p, accepted.vc, accepted.root_vc,
                                               accepted.enforce_result, accepted.steps, result)
        await self._input_required(updater, result,
                                   "The mandate defers this action to a decision (PENDING). "
                                   "Send a ratification signed by one of the listed authorities.")

    async def _input_required(self, updater: TaskUpdater, result: dict, text: str) -> None:
        msg = updater.new_agent_message(parts=[Part(text=text)])
        msg.metadata.update({EXTENSION_URI: {"result": result}})
        msg.extensions.append(EXTENSION_URI)
        self._observe(updater, result, TaskState.TASK_STATE_INPUT_REQUIRED)
        await updater.update_status(TaskState.TASK_STATE_INPUT_REQUIRED, message=msg,
                                    metadata={EXTENSION_URI: {"result": result}})

    async def _ratification(self, context: RequestContext, updater: TaskUpdater,
                            h: _Held) -> None:
        """Close a hold, or not, with the ratification record of -02 6.3 (spec 7.6)."""
        rat = extension_metadata(context.message)["ratification"]
        prior = {"core": h.enforce_result["core"], "core_digest": h.enforce_result["core_digest"]}
        try:
            record = enforce.ratify(prior, rat.get("decision"), rat.get("authority_proof"))
        except enforce.RatifyError as exc:
            # The handler screens the decision; anything else here is ours.
            log.error("ratification caller error on a held record: %s", exc)
            raise
        view = {k: record[k] for k in ("status", "decision", "authority", "core", "core_digest")}
        if record["status"] != enforce.RATIFIED:
            # The PENDING verdict stands; the task stays held (-02 6.3).
            result = {**h.hold_result, "ratification": view}
            with self.lock:
                h.hold_result = result
            await self._input_required(updater, result,
                                       f"Ratification not established: {record['reason']}. "
                                       "The action stays PENDING.")
            return
        with self.lock:
            self.held.pop(updater.task_id, None)
        p, vc = h.pending, h.vc
        if record["decision"] == enforce.DISAPPROVED:
            if vc["credentialSubject"]["aae"]["validity"].get("single_use") is True:
                self.verifier.single_use.release(vc["id"])
            r = Reject(6, "ratification_disapproved", record["reason"], h.enforce_result)
            await self._reject(updater, r, p.request_digest, ratification=view)
            return
        now = self.clock()
        try:
            self.verifier.check_temporal(vc, now, step=3)
        except Reject as r:
            await self._reject(updater, r, p.request_digest, ratification=view)
            return
        steps = sorted(set(h.steps) | {6})
        accepted = Accepted(vc=vc, root_vc=h.root_vc, last_step=steps[-1],
                            enforce_result=h.enforce_result, steps=steps)
        decision = Decision.bind(updater.task_id, p, accepted, now,
                                 self.cfg.skills[p.skill]["action"])
        await self._dispatch(updater, decision, ratification=view)

    def _observe(self, updater: TaskUpdater, result: dict, state: int) -> None:
        if self.observer is not None:
            self.observer(updater.task_id, result, TaskState.Name(state))

    async def _reject(self, updater: TaskUpdater, r: Reject, digest: str | None = None,
                      ratification: dict | None = None) -> None:
        result = {
            "verdict": "REJECT",
            "draft": AAE_DRAFT,
            "step": r.step,
            "step_name": STEP_NAMES.get(r.step, "unknown"),
            "reason_code": r.reason,
        }
        if digest is not None:
            result["request_digest"] = digest
        if r.detail:
            result["detail"] = r.detail
        if r.enforce_result is not None:
            result["enforce"] = _enforce_view(r.enforce_result)
        if ratification is not None:
            result["ratification"] = ratification
        text = f"AAE rejected at step {r.step} ({result['step_name']}): {r.reason}"
        msg = updater.new_agent_message(parts=[Part(text=text)])
        msg.metadata.update({EXTENSION_URI: {"result": result}})
        msg.extensions.append(EXTENSION_URI)
        self._observe(updater, result, TaskState.TASK_STATE_REJECTED)
        await updater.update_status(TaskState.TASK_STATE_REJECTED, message=msg,
                                    metadata={EXTENSION_URI: {"result": result}})


def _enforce_view(res: dict) -> dict:
    return {"verdict": res["verdict"], "core": res["core"], "core_digest": res["core_digest"]}


def _to_value(obj):
    from google.protobuf.struct_pb2 import Value
    v = Value()
    json_format.ParseDict(obj, v)
    return v


# --- ASGI app ----------------------------------------------------------------------

class ActivatedExtensionsHeader:
    """Echo the activated extensions in the A2A-Extensions response header
    (A2A extensions topic, "Extension Activation", step 3). The SDK version used
    here does not set it."""

    def __init__(self, app, supported: set[str]):
        self.app, self.supported = app, supported

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        requested: set[str] = set()
        for k, v in scope.get("headers", []):
            if k.decode("latin-1").lower() == A2A_EXTENSIONS_HEADER.lower():
                requested |= {u.strip() for u in v.decode("latin-1").split(",") if u.strip()}
        activated = sorted(requested & self.supported)

        async def send_wrapper(message):
            if message["type"] == "http.response.start" and activated:
                headers = list(message.get("headers", []))
                headers.append((A2A_EXTENSIONS_HEADER.encode(), ",".join(activated).encode()))
                message = {**message, "headers": headers}
            await send(message)

        return await self.app(scope, receive, send_wrapper)


def create_supplier_app(base_url: str, *, resolver: LocalDidResolver,
                        accepted_issuers: list[str] | None, own_aae: str | None = None,
                        clock=utc_now, verifier: AaeVerifier | None = None,
                        required: bool = True, binding: SubjectBinding | None = None,
                        audience: str | None = None, deferred_decisions: bool = False) -> tuple[Starlette, AgentCard, SupplierExecutor]:
    cfg = ProfileConfig(
        # audience is the endpoint URL unless fixed otherwise (the pinned bundle
        # names one audience wherever the supplier actually listens).
        audience=audience or base_url.rstrip("/") + RPC_PATH,
        skills={"get-quote": {"action": "read"}, "place-order": {"action": "pay"}},
        accepted_issuers=accepted_issuers,
        did_methods=["example"],
        required=required,
        own_aae=own_aae,
        deferred_decisions=deferred_decisions,
    )
    card = build_agent_card(base_url, cfg)
    assert find_extension_by_uri(card, EXTENSION_URI) is not None
    executor = SupplierExecutor(
        cfg=cfg,
        verifier=verifier or AaeVerifier(resolver, accepted_issuers=accepted_issuers),
        binding=binding or SubjectBinding(resolver),
        clock=clock,
    )
    handler = AaeRequestHandler(agent_executor=executor, task_store=InMemoryTaskStore(),
                                agent_card=card, required=cfg.required,
                                is_held=executor.is_held)
    routes = create_agent_card_routes(agent_card=card) + create_jsonrpc_routes(
        request_handler=handler, rpc_url=RPC_PATH)
    app = Starlette(routes=routes)
    app.add_middleware(ActivatedExtensionsHeader, supported={EXTENSION_URI})
    return app, card, executor
