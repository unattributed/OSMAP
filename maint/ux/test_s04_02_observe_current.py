"""Focused table test for the S04-02 current-observer capture boundary."""
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("s04_02_observe_current.py")


def require(value, message):
    if not value:
        raise RuntimeError(message)


def load_module():
    spec = importlib.util.spec_from_file_location("s04_02_observe_current", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def program(value=None, exit_status=0, raw=None, exception=None):
    if exception is not None:
        source = "raise " + exception + "\n"
    elif raw is not None:
        source = "print(" + repr(raw) + ")\nraise SystemExit(" + str(exit_status) + ")\n"
    elif value is None:
        source = "raise SystemExit(" + str(exit_status) + ")\n"
    else:
        source = (
            "import json\nprint(json.dumps(" + repr(value) + ",sort_keys=True))\n"
            "raise SystemExit(" + str(exit_status) + ")\n"
        )
    raw_source = source.encode("utf-8")
    return raw_source, hashlib.sha256(raw_source).hexdigest()


def backend(result="GAPS_PRESENT", cleanup=True, failure=None):
    return {
        "schema": "osmap-single-host-backend-prerequisite-v1",
        "result": result,
        "failure": failure,
        "cleanup_confirmed": cleanup,
        "host_file_writes": False,
        "database_writes": False,
        "public_service_operations": False,
        "authentication_requests": False,
        "raw_query_or_config_output_retained": False,
        "commands": [],
    }


def configuration():
    return {
        "schema": "osmap-single-host-current-config-map-v1",
        "result": "CAPTURE_PASS",
        "host_file_writes": False,
        "public_service_operations": False,
        "database_operations": False,
        "credential_operations": False,
        "contents_retained": False,
        "historical_hash_values_reused": False,
    }


def expect_refusal(module, observer, source, pin, category, checks=None):
    advanced = False
    try:
        module.capture(observer, source, pin)
        advanced = True
    except module.ObserverRefused as error:
        receipt = error.receipt
        require(receipt["observer"] == observer, category + ": observer identity lost")
        require(receipt["category"] == category, category + ": wrong refusal category")
        if checks is not None:
            checks(receipt)
    require(not advanced, category + ": failed admission advanced downstream")


def exercise():
    module = load_module()
    success, success_pin = program(backend())
    value, receipt = module.capture("backend", success, success_pin)
    require(value["result"] == "GAPS_PRESENT", "success result not parsed")
    require(receipt == {
        "observer": "backend",
        "exit_status": 0,
        "stdout_bytes": receipt["stdout_bytes"],
        "result": "GAPS_PRESENT",
        "reported_failure": None,
        "cleanup_status": True,
    }, "success receipt fields changed")

    config, config_pin = program(configuration())
    config_value, config_receipt = module.capture("config", config, config_pin)
    require(config_value["result"] == "CAPTURE_PASS", "config success not parsed")
    require(config_receipt["cleanup_status"] is None, "unreported cleanup was invented")

    failed = backend(result="REFUSED", cleanup=False, failure="READ_ONLY_COMMAND_REFUSED")
    nonzero, nonzero_pin = program(failed, exit_status=7)
    expect_refusal(
        module, "backend", nonzero, nonzero_pin, "NONZERO_EXIT",
        lambda receipt: require(
            receipt["exit_status"] == 7
            and receipt["result"] == "REFUSED"
            and receipt["reported_failure"] == "READ_ONLY_COMMAND_REFUSED"
            and receipt["cleanup_status"] is False
            and receipt["observer_result"] == failed
            and len(json.dumps(receipt, sort_keys=True).encode("utf-8")) < 49152,
            "nonzero structured failure evidence was not preserved",
        ),
    )

    malformed, malformed_pin = program(raw="{")
    missing, missing_pin = program()
    unexpected, unexpected_pin = program(exception="RuntimeError('must-not-be-retained')")
    uncertain, uncertain_pin = program(backend(cleanup=False))
    excessive, excessive_pin = program(raw="x" * (module.OUTPUT_CAP + 1))
    unsafe_value = backend()
    unsafe_value["database_writes"] = True
    unsafe, unsafe_pin = program(unsafe_value)
    cases = [
        (malformed, malformed_pin, "MALFORMED_STRUCTURED_OUTPUT"),
        (missing, missing_pin, "MISSING_STRUCTURED_OUTPUT"),
        (unexpected, unexpected_pin, "UNEXPECTED_EXCEPTION"),
        (uncertain, uncertain_pin, "CLEANUP_UNCONFIRMED"),
        (excessive, excessive_pin, "OUTPUT_BOUND_EXCEEDED"),
        (unsafe, unsafe_pin, "UNSAFE_RESULT_CLAIM"),
    ]
    for source, pin, category in cases:
        expect_refusal(module, "backend", source, pin, category)

    print(json.dumps({
        "schema": "osmap-s04-02-current-observer-focused-test-v1",
        "result": "PASS",
        "cases": 8,
        "optimized": not __debug__,
        "failed_admission_advanced": False,
    }, sort_keys=True))


def main():
    if "--child" in sys.argv:
        exercise()
        return 0
    commands = [
        [sys.executable, "-B", str(Path(__file__).resolve()), "--child"],
        [sys.executable, "-B", "-O", str(Path(__file__).resolve()), "--child"],
    ]
    results = []
    for command in commands:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        require(completed.returncode == 0, "focused child failed: " + completed.stderr[:512])
        result = json.loads(completed.stdout)
        require(result["result"] == "PASS", "focused child did not pass")
        results.append(result)
    require([result["optimized"] for result in results] == [False, True], "optimized-mode coverage missing")
    print(json.dumps({
        "schema": "osmap-s04-02-current-observer-focused-matrix-v1",
        "result": "PASS",
        "runs": results,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
