# SPDX-License-Identifier: ISC
# -*- coding: utf-8 eval: (blacken-mode 1) -*-

"""
Test mgmtd gRPC Execute RPC dispatch to backend clients.
"""

import json
import os
import threading

import pytest
from lib.common_config import retry
from lib.micronet import commander
from lib.topogen import Topogen, TopoRouter
from lib.topotest import json_cmp

CWD = os.path.dirname(os.path.realpath(__file__))
GRPCP_MGMTD = 50057
script_path = os.path.realpath(os.path.join(CWD, "../lib/grpc-query.py"))

pytestmark = [pytest.mark.ripd, pytest.mark.mgmtd]

try:
    import grpc  # noqa: F401
    import grpc_tools  # noqa: F401
except ImportError:
    pytest.skip("skipping; gRPC modules not installed", allow_module_level=True)

try:
    commander.cmd_raises([script_path, "--check"])
except Exception:
    pytest.skip(
        "skipping; cannot create or import gRPC proto modules",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        mgmtd_options = f"-M grpc:{GRPCP_MGMTD}"
        router.load_config(TopoRouter.RD_MGMTD, "", mgmtd_options)

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


@retry(retry_timeout=30)
def check_client_connect(r1):
    out = r1.vtysh_cmd("show mgmt backend-adapter all")
    return None if "mgmtd-testc" in out else "missing mgmtd-testc"


def run_grpc_client(r, commands):
    if not isinstance(commands, str):
        commands = "\n".join(commands) + "\n"
    if not commands.endswith("\n"):
        commands += "\n"
    return r.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=commands)


def run_testc_for_rpc(r1, command, expect_testc_json=True):
    be_client_path = os.path.join(r1.net.daemondir, "mgmtd_testc")
    rc, _, _ = r1.net.cmd_status(be_client_path + " --help")
    if rc:
        pytest.skip("No mgmtd_testc")

    out = []

    def run_testc():
        output = r1.net.cmd_raises(
            be_client_path + " --timeout 10 --log file:mgmtd-testc.log"
        )
        if expect_testc_json:
            out.append(json.loads(output))

    t = threading.Thread(target=run_testc)
    t.start()

    res = check_client_connect(r1)
    assert res is None

    output = run_grpc_client(r1, command)

    t.join()
    return output, out


def test_execute_rpc_via_mgmtd_grpc(tgen):
    r1 = tgen.gears["r1"]

    output, testc_output = run_testc_for_rpc(
        r1, "EXEC,/frr-ripd:clear-rip-route,vrf=testname"
    )
    assert "output" not in output

    expected = {"frr-ripd:clear-rip-route": {"vrf": "testname"}}
    result = json_cmp(testc_output[0], expected)
    assert result is None


def test_execute_rpc_output_via_mgmtd_grpc(tgen):
    r1 = tgen.gears["r1"]

    output, _ = run_testc_for_rpc(
        r1, "EXEC,/frr-zebra:get-vrf-info", expect_testc_json=False
    )

    assert "path: \"/frr-zebra:get-vrf-info/vrf-list[name='default']/name\"" in output
    assert 'value: "default"' in output
    assert "path: \"/frr-zebra:get-vrf-info/vrf-list[name='default']/vrf-id\"" in output
    assert 'value: "0"' in output
