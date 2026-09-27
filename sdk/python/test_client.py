import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pgws import Client, Error

RESOURCE = "00000000-0000-4000-8000-000000000001"

class SDKTest(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.responses = []
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self): self.respond()
            def do_POST(self): self.respond()
            def respond(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                fixture.requests.append((self.path, self.headers.get("Idempotency-Key"), self.headers.get("Authorization"), json.loads(raw) if raw else None))
                status, body = fixture.responses.pop(0)
                self.send_response(status)
                if status == 307:
                    self.send_header("Location", "/leaked-token")
                data = json.dumps(body).encode()
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.client = Client("http://127.0.0.1:" + str(self.server.server_port), RESOURCE, "private-token")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_wait_preserves_terminal_error(self):
        self.responses = [(200, {"status":"running"}), (200, {"status":"failed", "error":{"code":"SOURCE_LINEAGE_CHANGED", "retryable":False}})]
        with self.assertRaises(Error) as failure:
            self.client.wait(RESOURCE, interval=0.001)
        self.assertEqual(failure.exception.code, "SOURCE_LINEAGE_CHANGED")
        self.assertFalse(failure.exception.retryable)
        self.assertEqual(len(self.requests), 2)

    def test_retries_keep_supplied_key_and_redirects_do_not_forward_token(self):
        self.responses = [(503, {"code":"OPERATION_PENDING", "retryable":True}), (200, {"barrier_token":"same"}), (307, {})]
        with self.assertRaises(Error) as failure:
            self.client.barrier(RESOURCE, key="stable-key")
        self.assertTrue(failure.exception.retryable)
        self.client.barrier(RESOURCE, key="stable-key")
        self.assertEqual([r[1] for r in self.requests], ["stable-key", "stable-key"])
        with self.assertRaises(Error) as failure:
            self.client.baselines()
        self.assertEqual(failure.exception.status, 307)
        self.assertEqual(len(self.requests), 3)

    def test_no_implicit_write_key(self):
        with self.assertRaises(ValueError):
            self.client.create(RESOURCE, "task", key="")
        self.assertEqual(self.requests, [])

    def test_reseed_epoch_and_stable_key(self):
        self.responses = [(202, {"source_epoch": 2}), (202, {"source_epoch": 2})]
        for _ in range(2):
            self.client.reseed_source(RESOURCE, 1, key="reseed-request")
        self.assertEqual(self.requests[0], self.requests[1])
        self.assertTrue(self.requests[0][0].endswith("/sources/" + RESOURCE + "/actions"))
        self.assertEqual(self.requests[0][3], {"action": "reseed", "expected_source_epoch": 1})
        for epoch in (0, True, 1.5, 1_000_000_000):
            with self.assertRaises(ValueError):
                self.client.reseed_source(RESOURCE, epoch, key="invalid")
        self.assertEqual(len(self.requests), 2)

    def test_usage_keeps_decimal_amounts_and_encodes_cursor(self):
        self.responses = [(200, {"items": [{"amount": "9007199254740993"}], "measurement_kind": "observed_gauge"})]
        result = self.client.usage(cursor="next+/=", limit=2)
        self.assertEqual(result["items"][0]["amount"], "9007199254740993")
        self.assertTrue(self.requests[0][0].endswith("/usage?limit=2&cursor=next%2B%2F%3D"))
        self.assertIsNone(self.requests[0][1])

if __name__ == "__main__": unittest.main()
