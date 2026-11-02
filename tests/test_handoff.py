"""Verifier-to-executor handoff (XR-HANDOFF).

A decision accepted on task A does not authorize the skill invocation of task
B, even when one reusable AAE authorizes both. Three pairings, each from an
equivalent initial state (a fresh supplier):

  A with A's receiving context  -> one skill call, argument = frozen request A
  B with B's receiving context  -> one skill call, argument = frozen request B
  A's decision, B's context     -> zero skill calls, refused at the handoff for
                                   decision_task_mismatch, not for a spent
                                   challenge, a consumed single-use grant or a
                                   terminal task

The AAE is reusable (single_use false), both challenges are answered
correctly, and A's decision is not altered; only the dispatch association is.
"""
from __future__ import annotations

import asyncio
import pytest

from a2a.types import TaskState

from aae_a2a.buyer import task_result
from aae_a2a.challenge import utc_now
from aae_a2a.digest import request_bytes, request_digest
from aae_a2a.server import HandoffMismatch, perform_skill
from aae_a2a.testkeys import demo_resolver, did_of, issue_buyer_aae, issue_supplier_aae
from aae_a2a.server import create_supplier_app

from .conftest import BASE_URL, DOMAINS, Env, run

REQ_A = {"skill": "place-order",
         "transaction": {"amount": 120, "currency": "EUR",
                         "items": [{"sku": "PAPER-A4", "qty": 20}]}}
REQ_B = {"skill": "place-order",
         "transaction": {"amount": 80, "currency": "EUR",
                         "items": [{"sku": "TONER-K1", "qty": 2}]}}


def fresh_env() -> tuple[Env, list, list]:
    """A new supplier with a call log on the skill and a log of handoffs."""
    app, _card, executor = create_supplier_app(
        BASE_URL, resolver=demo_resolver(), accepted_issuers=[did_of("issuer")],
        own_aae=issue_supplier_aae(utc_now()))
    calls: list = []
    handoffs: list = []

    def logged_perform(skill, tx):
        calls.append({"skill": skill, "transaction": tx})
        return perform_skill(skill, tx)

    executor.perform = logged_perform
    original = executor._dispatch

    async def logged_dispatch(updater, decision, ratification=None):
        handoffs.append((updater.task_id, decision))
        await original(updater, decision, ratification)

    executor._dispatch = logged_dispatch
    return Env(app=app, executor=executor), calls, handoffs


def reusable_aae() -> str:
    return issue_buyer_aae(utc_now(), DOMAINS, single_use=False)


async def _send(env, req, aae):
    buyer = await env.discovered()
    return await buyer.request(req["skill"], req["transaction"], aae=aae)


def _own_context(req):
    env, calls, handoffs = fresh_env()
    task = run(_send(env, req, reusable_aae()))
    return task, calls, handoffs


@pytest.mark.parametrize("req", [REQ_A, REQ_B], ids=["A-own-context", "B-own-context"])
def test_decision_in_own_context_invokes_once_with_frozen_request(req):
    task, calls, handoffs = _own_context(req)
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    # Exactly one skill call, argument equal to the frozen request.
    assert calls == [req]
    # Positive binding: the one handoff carried a decision for this task, whose
    # frozen bytes are the request sent, and the receipt names the same digest.
    assert len(handoffs) == 1
    receiving_task, decision = handoffs[0]
    assert decision.task_id == receiving_task == task.id
    assert decision.request_bytes == request_bytes(req)
    assert decision.frozen_request() == req
    assert task_result(task)["request_digest"] == decision.request_digest == request_digest(req)


def test_decision_of_a_refused_in_context_of_b():
    """A's accepted decision is handed to B's receiving context: zero calls."""
    env, calls, handoffs = fresh_env()
    executor = env.executor
    verified_dispatch = type(executor)._dispatch.__get__(executor)
    aae = reusable_aae()
    a_decision: dict = {}
    a_ready, swap_done = asyncio.Event(), asyncio.Event()
    swap: dict = {}

    async def intercept(updater, decision, ratification=None):
        if "a" not in a_decision:
            # Task A: keep its decision unchanged and wait until B has tried it.
            a_decision["a"], a_decision["a_task"] = decision, updater.task_id
            a_ready.set()
            await asyncio.wait_for(swap_done.wait(), 5)
            await verified_dispatch(updater, decision, ratification)
            return
        # Task B: its own decision is set aside; A's is offered instead.
        await a_ready.wait()
        swap["b_task"], swap["b_decision"] = updater.task_id, decision
        swap["calls_before"] = len(calls)
        try:
            await verified_dispatch(updater, a_decision["a"])
        except HandoffMismatch as exc:
            swap["reason"] = exc.reason
        swap["calls_after"] = len(calls)
        swap_done.set()

    executor._dispatch = intercept

    async def scenario():
        buyer_a, buyer_b = await env.discovered(), await env.discovered()
        task_a = asyncio.create_task(
            buyer_a.request(REQ_A["skill"], REQ_A["transaction"], aae=aae))
        await asyncio.wait_for(a_ready.wait(), 5)
        task_b = await buyer_b.request(REQ_B["skill"], REQ_B["transaction"], aae=aae)
        return await task_a, task_b

    task_a, task_b = run(scenario())

    # Zero skill calls for the mismatched pairing, refused at the handoff.
    assert swap["calls_before"] == swap["calls_after"] == 0
    assert swap["reason"] == "decision_task_mismatch"
    # Not one of the refusals that would not exercise the binding: B's own
    # challenge passed (B reached the handoff with a decision of its own), the
    # AAE is reusable so no use was consumed, and B is not in a terminal state.
    assert swap["b_decision"].task_id == swap["b_task"] == task_b.id
    assert swap["b_decision"].accepted.vc["credentialSubject"]["aae"]["validity"]["single_use"] is False
    assert task_b.status.state not in (TaskState.TASK_STATE_COMPLETED, TaskState.TASK_STATE_FAILED,
                                       TaskState.TASK_STATE_REJECTED, TaskState.TASK_STATE_CANCELED)
    # A's decision was not altered and stays valid in its own context: after
    # the refused pairing it runs A, once, with A's frozen request.
    assert a_decision["a_task"] == a_decision["a"].task_id == task_a.id
    assert task_a.status.state == TaskState.TASK_STATE_COMPLETED
    assert calls == [REQ_A]
    assert task_result(task_a)["request_digest"] == request_digest(REQ_A)
