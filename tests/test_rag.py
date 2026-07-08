import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_modeler import attack_rag
from threat_modeler.graph import GComponent


class _RagStub(BaseHTTPRequestHandler):
    seen_body = {}

    def log_message(self, *_a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        type(self).seen_body = json.loads(self.rfile.read(length) or b"{}")
        payload = {
            "query": type(self).seen_body.get("query"),
            "result_count": 1,
            "results": [{
                "collection": "attack_knowledge_chunks", "id": "chunk-1",
                "rank": 1, "score": 1.0, "document": "retrieved text",
                "source": {"corpus": "mitre_attack_enterprise",
                           "external_id": "T1059", "name": "Command and Scripting Interpreter",
                           "url": "https://attack.mitre.org/techniques/T1059/",
                           "source_locator": "$.objects[1]"},
            }],
        }
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class TestAttackRag(unittest.TestCase):
    def test_build_component_query_from_config(self):
        comp = GComponent(
            id="c1", label="Flight Controller", type="process",
            software={"os": "NuttX RTOS", "sbom": ["PX4 1.14"], "services": ["MAVLink"]},
            hardware={"chips": ["STM32H743"], "modules": [], "debug": ""},
            custom=[],
        )
        q = attack_rag.build_component_query(comp, protocols=["MAVLink v2", "MAVLink v2"])
        self.assertIn("Flight Controller", q)
        self.assertIn("NuttX RTOS", q)
        self.assertIn("STM32H743", q)
        self.assertEqual(q.lower().count("mavlink v2"), 1)  # de-duplicated

    def test_query_and_findings(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _RagStub)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            resp = attack_rag.attack_rag_query("T1059", top_k=5, base_url=base)
        finally:
            server.shutdown()
            t.join(timeout=2)
            server.server_close()
        self.assertEqual(_RagStub.seen_body["query"], "T1059")
        self.assertEqual(_RagStub.seen_body["top_k"], 5)
        findings = attack_rag.rag_findings(resp)
        self.assertEqual(findings[0]["id"], "T1059")
        self.assertIn("Command and Scripting", findings[0]["name"])

    def test_fail_closed_on_unreachable_server(self):
        # unroutable port -> RAGError (fail closed, never fabricate)
        with self.assertRaises(attack_rag.RAGError):
            attack_rag.attack_rag_query("T1059", base_url="http://127.0.0.1:1", timeout=1)

    def test_query_validation(self):
        with self.assertRaises(ValueError):
            attack_rag.attack_rag_query("   ")
        with self.assertRaises(ValueError):
            attack_rag.attack_rag_query("x", top_k=0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
