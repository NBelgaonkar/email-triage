"""Exercise the real Gmail wrapper and run_once loop against a fake googleapiclient service."""
import base64
import email as pyemail

from conftest import FakeClassifier, decision, raw_msg

from triage.agent import Agent
from triage.gmail_client import Gmail
from triage.main import run_once


class Req:
    def __init__(self, fn):
        self.fn = fn

    def execute(self):
        return self.fn()


class FakeService:
    def __init__(self, msgs):
        self.msgs = {m["id"]: m for m in msgs}
        self.label_store = [{"id": "INBOX", "name": "INBOX"}]
        self.queries, self.sent, self.draft_log = [], [], []

    def users(self):
        return self

    def labels(self):
        svc = self

        class L:
            def list(self, userId):
                return Req(lambda: {"labels": svc.label_store})

            def create(self, userId, body):
                lab = {"id": f"Label_{len(svc.label_store)}", "name": body["name"]}
                svc.label_store.append(lab)
                return Req(lambda: lab)

        return L()

    def messages(self):
        svc = self

        class M:
            def list(self, userId, q, maxResults):
                svc.queries.append(q)
                excluded = [l["id"] for l in svc.label_store if l["name"].endswith("/Processed")]
                ids = [m for m, v in svc.msgs.items() if not set(v["labelIds"]) & set(excluded)]
                return Req(lambda: {"messages": [{"id": i} for i in ids]})

            def get(self, userId, id, format):
                return Req(lambda: svc.msgs[id])

            def modify(self, userId, id, body):
                def do():
                    labs = svc.msgs[id]["labelIds"]
                    svc.msgs[id]["labelIds"] = [l for l in labs if l not in body["removeLabelIds"]] + body["addLabelIds"]
                    return {}
                return Req(do)

            def send(self, userId, body):
                svc.sent.append(body)
                return Req(lambda: {"id": "sent1"})

        return M()

    def drafts(self):
        svc = self

        class D:
            def create(self, userId, body):
                svc.draft_log.append(body)
                return Req(lambda: {"id": "d1"})

        return D()


class Notes:
    def __init__(self):
        self.texts = []

    def send(self, t):
        self.texts.append(t)


def test_full_loop_with_real_wrapper(cfg, state):
    msgs = [
        raw_msg(id="a", thread="ta", body="Thanks for the help!"),
        raw_msg(id="b", thread="tb", body="Can we schedule a call Friday?"),
    ]
    svc = FakeService(msgs)
    g = Gmail(creds=None, service=svc)
    labels = g.ensure_labels()
    assert set(labels) >= {"Processed", "Escalated", "Drafted"}
    assert g.processed_query_term() == "-label:ai-triage-processed"

    clf = FakeClassifier(decision())
    notes = Notes()
    agent = Agent(cfg, g, clf, notes, state)
    assert run_once(agent) == 2
    assert "in:inbox is:unread after:" in svc.queries[0]

    # a: draft threaded correctly; b: escalated by keyword rule despite model saying reply
    assert len(svc.draft_log) == 1 and svc.draft_log[0]["message"]["threadId"] == "ta"
    raw = base64.urlsafe_b64decode(svc.draft_log[0]["message"]["raw"])
    m = pyemail.message_from_bytes(raw)
    assert m["To"] == "jane@example.com" and m["Subject"] == "Re: Hello"
    assert len(notes.texts) == 1 and "scheduling" in notes.texts[0]
    assert labels["Escalated"] in svc.msgs["b"]["labelIds"]

    # Second poll: nothing new, nothing redone
    assert run_once(agent) == 0
    assert len(svc.draft_log) == 1 and len(notes.texts) == 1 and clf.calls == 2


def test_ensure_labels_idempotent():
    svc = FakeService([])
    Gmail(creds=None, service=svc).ensure_labels()
    n = len(svc.label_store)
    Gmail(creds=None, service=svc).ensure_labels()
    assert len(svc.label_store) == n
