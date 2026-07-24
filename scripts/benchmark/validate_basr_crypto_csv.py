#!/usr/bin/env python3
import csv
import sys
from collections import defaultdict
from pathlib import Path


EXPECTED_HEADER = [
    "scheme",
    "experiment",
    "profile",
    "run",
    "n",
    "ns",
    "nr",
    "report_size_bytes",
    "sign_ns",
    "kem_encap_ns",
    "aead_encrypt_ns",
    "privacy_ns",
    "sigverify_ns",
    "aggregate_ns",
    "aggverify_ns",
    "total_crypto_ns",
    "kem_decap_ns",
    "aead_decrypt_ns",
    "recovery_ns",
    "accepted_count",
    "correctness",
]

PROFILE_SCENARIOS = {
    "smoke": {
        "size_sweep": [2, 4],
        "sensitive_sweep": [1, 2],
        "recovery_sweep": [1, 2],
    },
    "full": {
        "size_sweep": [50, 100, 200, 400, 600, 800, 1000],
        "sensitive_sweep": [10, 30, 70, 120, 170, 190],
        "recovery_sweep": [10, 30, 70, 120, 170, 190],
    },
}


def read_metadata(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Malformed metadata line: {raw_line!r}")
        key, value = line.split("=", 1)
        values[key] = value
    return values


def as_int(row: dict[str, str], name: str) -> int:
    value = row[name]
    if value == "":
        raise ValueError(f"Missing integer field {name}")
    return int(value)


def require_blank(row: dict[str, str], *names: str) -> None:
    for name in names:
        if row[name] != "":
            raise ValueError(
                f"Expected blank {name}, found {row[name]!r}"
            )


def require_nonnegative(
    row: dict[str, str],
    *names: str,
) -> None:
    for name in names:
        value = as_int(row, name)
        if value < 0:
            raise ValueError(f"{name} is negative: {value}")


def validate_crypto_row(row: dict[str, str]) -> None:
    require_blank(
        row,
        "nr",
        "kem_decap_ns",
        "aead_decrypt_ns",
        "recovery_ns",
    )
    require_nonnegative(
        row,
        "sign_ns",
        "kem_encap_ns",
        "aead_encrypt_ns",
        "privacy_ns",
        "sigverify_ns",
        "aggregate_ns",
        "aggverify_ns",
        "total_crypto_ns",
    )

    sign_ns = as_int(row, "sign_ns")
    kem_encap_ns = as_int(row, "kem_encap_ns")
    aead_encrypt_ns = as_int(row, "aead_encrypt_ns")
    privacy_ns = as_int(row, "privacy_ns")
    sigverify_ns = as_int(row, "sigverify_ns")
    aggregate_ns = as_int(row, "aggregate_ns")
    aggverify_ns = as_int(row, "aggverify_ns")
    total_crypto_ns = as_int(row, "total_crypto_ns")

    if privacy_ns != kem_encap_ns + aead_encrypt_ns:
        raise ValueError(
            "privacy_ns != kem_encap_ns + aead_encrypt_ns"
        )

    expected_total = (
        sign_ns
        + privacy_ns
        + sigverify_ns
        + aggregate_ns
        + aggverify_ns
    )
    if total_crypto_ns != expected_total:
        raise ValueError(
            f"total_crypto_ns mismatch: "
            f"{total_crypto_ns} != {expected_total}"
        )

    if as_int(row, "accepted_count") != as_int(row, "n"):
        raise ValueError("accepted_count must equal n")

    if row["experiment"] == "size_sweep":
        if as_int(row, "ns") != 0:
            raise ValueError("size_sweep must use ns=0")
        if kem_encap_ns != 0 or aead_encrypt_ns != 0:
            raise ValueError(
                "size_sweep with ns=0 must have zero "
                "privacy primitive times"
            )


def validate_recovery_row(row: dict[str, str]) -> None:
    require_blank(
        row,
        "sign_ns",
        "kem_encap_ns",
        "aead_encrypt_ns",
        "privacy_ns",
        "sigverify_ns",
        "aggregate_ns",
        "aggverify_ns",
        "total_crypto_ns",
    )
    require_nonnegative(
        row,
        "kem_decap_ns",
        "aead_decrypt_ns",
        "recovery_ns",
    )

    kem_decap_ns = as_int(row, "kem_decap_ns")
    aead_decrypt_ns = as_int(row, "aead_decrypt_ns")
    recovery_ns = as_int(row, "recovery_ns")

    if recovery_ns != kem_decap_ns + aead_decrypt_ns:
        raise ValueError(
            "recovery_ns != kem_decap_ns + aead_decrypt_ns"
        )

    if as_int(row, "ns") != as_int(row, "n"):
        raise ValueError("recovery fixture must use ns=n")

    nr = as_int(row, "nr")
    n = as_int(row, "n")
    if not 0 < nr <= n:
        raise ValueError("recovery nr must satisfy 0 < nr <= n")

    if as_int(row, "accepted_count") != n:
        raise ValueError("recovery accepted_count must equal n")


def scenario_key(
    row: dict[str, str],
) -> tuple[str, int]:
    experiment = row["experiment"]
    if experiment == "size_sweep":
        return experiment, as_int(row, "n")
    if experiment == "sensitive_sweep":
        return experiment, as_int(row, "ns")
    if experiment == "recovery_sweep":
        return experiment, as_int(row, "nr")
    raise ValueError(f"Unknown experiment: {experiment!r}")


def main() -> int:
    if len(sys.argv) != 2:
        print(
            "Usage: validate_basr_crypto_csv.py "
            "<output-directory>",
            file=sys.stderr,
        )
        return 2

    output_dir = Path(sys.argv[1])
    csv_path = output_dir / "basr-crypto-raw.csv"
    metadata_path = (
        output_dir / "basr-crypto-metadata.txt"
    )

    if not csv_path.is_file():
        raise FileNotFoundError(csv_path)
    if not metadata_path.is_file():
        raise FileNotFoundError(metadata_path)

    metadata = read_metadata(metadata_path)
    profile = metadata["profile"]
    measurement_runs = int(
        metadata["measurement_runs"]
    )
    report_size = int(
        metadata["report_size_bytes"]
    )

    if profile not in PROFILE_SCENARIOS:
        raise ValueError(
            f"Unsupported profile: {profile}"
        )

    with csv_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != EXPECTED_HEADER:
            raise ValueError(
                f"Unexpected CSV header:\n"
                f"{reader.fieldnames}"
            )
        rows = list(reader)

    expected_scenario_count = sum(
        len(values)
        for values
        in PROFILE_SCENARIOS[profile].values()
    )
    expected_rows = (
        expected_scenario_count
        * measurement_runs
    )

    if len(rows) != expected_rows:
        raise ValueError(
            f"Unexpected row count: "
            f"{len(rows)} != {expected_rows}"
        )

    runs_by_scenario: dict[
        tuple[str, int],
        list[int],
    ] = defaultdict(list)

    for line_number, row in enumerate(
        rows,
        start=2,
    ):
        try:
            if row["scheme"] != "BASR":
                raise ValueError(
                    "scheme must be BASR"
                )
            if row["profile"] != profile:
                raise ValueError(
                    "row profile differs from metadata"
                )
            if row["correctness"].lower() != "true":
                raise ValueError(
                    "correctness must be true"
                )
            if (
                as_int(row, "report_size_bytes")
                != report_size
            ):
                raise ValueError(
                    "report size differs from metadata"
                )

            experiment = row["experiment"]
            if experiment in {
                "size_sweep",
                "sensitive_sweep",
            }:
                validate_crypto_row(row)
            elif experiment == "recovery_sweep":
                validate_recovery_row(row)
            else:
                raise ValueError(
                    f"Unknown experiment: "
                    f"{experiment!r}"
                )

            key = scenario_key(row)
            runs_by_scenario[key].append(
                as_int(row, "run")
            )
        except Exception as exc:
            raise ValueError(
                f"CSV line {line_number}: {exc}"
            ) from exc

    expected_keys: set[tuple[str, int]] = set()
    for experiment, values in (
        PROFILE_SCENARIOS[profile].items()
    ):
        expected_keys.update(
            (experiment, value)
            for value in values
        )

    actual_keys = set(runs_by_scenario)
    if actual_keys != expected_keys:
        missing = expected_keys - actual_keys
        extra = actual_keys - expected_keys
        raise ValueError(
            f"Scenario mismatch; "
            f"missing={sorted(missing)}, "
            f"extra={sorted(extra)}"
        )

    expected_runs = list(
        range(1, measurement_runs + 1)
    )
    for key, observed_runs in (
        runs_by_scenario.items()
    ):
        if sorted(observed_runs) != expected_runs:
            raise ValueError(
                f"Run numbers for {key} are "
                f"{sorted(observed_runs)}, expected "
                f"{expected_runs}"
            )

    print("BASR crypto CSV validation: PASS")
    print(f"profile={profile}")
    print(f"rows={len(rows)}")
    print(
        f"measurement_runs={measurement_runs}"
    )
    print(
        f"scenarios={len(runs_by_scenario)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            f"VALIDATION FAILED: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(1)