import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_modeler.llm import call_and_parse


class _OllamaStub(BaseHTTPRequestHandler):
    seen_path = ""
    seen_body = {}

    def log_message(self, *_args):
        pass

    def do_POST(self):
        type(self).seen_path = self.path
        length = int(self.headers.get("Content-Length", 0))
        type(self).seen_body = json.loads(self.rfile.read(length) or b"{}")
        payload = {
            "model": type(self).seen_body.get("model"),
            "message": {"role": "assistant", "content": '{"ok": true}'},
            "done": True,
        }
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _OpenAIStub(BaseHTTPRequestHandler):
    seen_path = ""
    seen_body = {}
    seen_auth = ""

    def log_message(self, *_args):
        pass

    def do_POST(self):
        type(self).seen_path = self.path
        type(self).seen_auth = self.headers.get("Authorization", "")
        length = int(self.headers.get("Content-Length", 0))
        type(self).seen_body = json.loads(self.rfile.read(length) or b"{}")
        payload = {"choices": [
            {"message": {"role": "assistant", "content": '{"ok": true}'}, "finish_reason": "stop"}
        ]}
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class TestOpenAIProvider(unittest.TestCase):
    def test_call_and_parse_uses_openai_chat_completions(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _OpenAIStub)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/v1"
            got = call_and_parse(
                "sk-test", "meta-llama/llama-3.1-70b-instruct",
                "system prompt", "user prompt",
                provider="openai", base_url=base,
            )
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()

        self.assertEqual(got, {"ok": True})
        self.assertEqual(_OpenAIStub.seen_path, "/v1/chat/completions")
        self.assertEqual(_OpenAIStub.seen_auth, "Bearer sk-test")
        self.assertEqual(_OpenAIStub.seen_body["model"], "meta-llama/llama-3.1-70b-instruct")
        self.assertFalse(_OpenAIStub.seen_body["stream"])


class TestOllamaProvider(unittest.TestCase):
    def test_call_and_parse_uses_ollama_chat_api(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _OllamaStub)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            got = call_and_parse(
                "",
                "local-test-model",
                "system prompt",
                "user prompt",
                provider="ollama",
                base_url=base,
            )
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()

        self.assertEqual(got, {"ok": True})
        self.assertEqual(_OllamaStub.seen_path, "/api/chat")
        self.assertEqual(_OllamaStub.seen_body["model"], "local-test-model")
        self.assertFalse(_OllamaStub.seen_body["stream"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
