from datetime import datetime, timedelta, timezone

import httpx

from slopwatch.registry import _classify, check_npm, check_pypi, import_to_pypi


def iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def test_import_mapping():
    assert import_to_pypi("cv2") == "opencv-python"
    assert import_to_pypi("snap7") == "python-snap7"
    assert import_to_pypi("Some_Lib") == "some-lib"
    assert import_to_pypi("utils") is None   # local module, can't judge
    assert import_to_pypi("google") is None  # namespace package


def test_classify():
    assert _classify(iso(400), True) == "established"
    assert _classify(iso(10), True) == "new"
    assert _classify(None, False) == "empty"


def _client(routes: dict) -> httpx.Client:
    def handler(req: httpx.Request) -> httpx.Response:
        for prefix, (code, body) in routes.items():
            if str(req.url).startswith(prefix):
                return httpx.Response(code, json=body)
        return httpx.Response(404, json={})
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_pypi_missing_and_new():
    c = _client({
        "https://pypi.org/pypi/realpkg/": (200, {"info": {"summary": "x"},
                                                 "releases": {"1.0": [{"upload_time_iso_8601": iso(5)}]}}),
    })
    assert check_pypi(c, "fakepkg")["status"] == "missing"
    res = check_pypi(c, "realpkg")
    assert res["status"] == "new" and res["n_versions"] == 1


def test_npm_scoped_and_established():
    many = {"versions": {str(i): {} for i in range(25)}, "modified": iso(1)}
    c = _client({"https://registry.npmjs.org/@scope%2Fbig": (200, many)})
    assert check_npm(c, "@scope/big")["status"] == "established"
    assert check_npm(c, "nope-not-real")["status"] == "missing"
