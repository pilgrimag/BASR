#!/usr/bin/env python3
"""
Analyze BASR full cryptographic benchmark raw data.

Outputs, without modifying the raw CSV:
  - basr-crypto-summary-long.csv
  - basr-crypto-outliers.csv
  - basr-crypto-figure-data.csv
  - basr-crypto-quality-report.txt
  - analysis-checksums.sha256
"""

from __future__ import annotations

import csv
import hashlib
import math
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


RAW_NAME = "basr-crypto-raw.csv"
METADATA_NAME = "basr-crypto-metadata.txt"

EXPECTED_PROFILE = "full"
EXPECTED_MEASUREMENTS = 30
EXPECTED_ROWS = 570

SIZE_VALUES = [50, 100, 200, 400, 600, 800, 1000]
SENSITIVE_VALUES = [10, 30, 70, 120, 170, 190]
RECOVERY_VALUES = [10, 30, 70, 120, 170, 190]

BASE_METRICS = [
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
]

SUMMARY_HEADER = [
    "experiment",
    "n",
    "ns",
    "nr",
    "x_name",
    "x_value",
    "metric",
    "samples",
    "mean_ns",
    "median_ns",
    "stdev_ns",
    "cv",
    "min_ns",
    "p25_ns",
    "p75_ns",
    "p95_ns",
    "max_ns",
    "iqr_ns",
    "iqr_outlier_count",
    "iqr_outlier_fraction",
]

OUTLIER_HEADER = [
    "experiment",
    "n",
    "ns",
    "nr",
    "run",
    "metric",
    "value_ns",
    "q1_ns",
    "q3_ns",
    "iqr_ns",
    "lower_fence_ns",
    "upper_fence_ns",
]

FIGURE_HEADER = [
    "figure",
    "x_name",
    "x_value",
    "series",
    "metric",
    "samples",
    "mean_ms",
    "median_ms",
    "stdev_ms",
    "p25_ms",
    "p75_ms",
    "p95_ms",
    "min_ms",
    "max_ms",
    "iqr_outlier_count",
]


@dataclass(frozen=True)
class Scenario:
    experiment: str
    n: int
    ns: int
    nr: int | None

    @property
    def x_name(self) -> str:
        if self.experiment == "size_sweep":
            return "n"
        if self.experiment == "sensitive_sweep":
            return "ns"
        if self.experiment == "recovery_sweep":
            return "nr"
        raise ValueError(f"Unknown experiment: {self.experiment}")

    @property
    def x_value(self) -> int:
        if self.x_name == "n":
            return self.n
        if self.x_name == "ns":
            return self.ns
        assert self.nr is not None
        return self.nr


@dataclass(frozen=True)
class MetricStats:
    samples: int
    mean: float
    median: float
    stdev: float
    cv: float | None
    minimum: float
    p25: float
    p75: float
    p95: float
    maximum: float
    iqr: float
    outlier_count: int
    outlier_fraction: float
    lower_fence: float
    upper_fence: float


def fail(message: str) -> None:
    raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_metadata(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "=" not in line:
            fail(f"Malformed metadata line: {raw_line!r}")
        key, value = line.split("=", 1)
        result[key] = value
    return result


def parse_optional_int(value: str) -> int | None:
    return None if value == "" else int(value)


def parse_required_int(row: dict[str, str], name: str) -> int:
    value = row[name]
    if value == "":
        fail(f"Missing required integer field {name}")
    return int(value)


def percentile(values: list[float], probability: float) -> float:
    if not values:
        fail("Cannot compute a percentile of an empty list")
    if not 0.0 <= probability <= 1.0:
        fail(f"Invalid percentile probability: {probability}")

    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]

    position = (len(ordered) - 1) * probability
    lower_index = math.floor(position)
    upper_index = math.ceil(position)

    if lower_index == upper_index:
        return ordered[lower_index]

    fraction = position - lower_index
    return (
        ordered[lower_index]
        + fraction * (ordered[upper_index] - ordered[lower_index])
    )


def compute_stats(values: list[float]) -> MetricStats:
    if not values:
        fail("Metric has no values")

    mean = statistics.fmean(values)
    median = statistics.median(values)
    stdev = statistics.stdev(values) if len(values) >= 2 else 0.0
    cv = None if mean == 0.0 else stdev / mean

    p25 = percentile(values, 0.25)
    p75 = percentile(values, 0.75)
    p95 = percentile(values, 0.95)
    iqr = p75 - p25
    lower_fence = p25 - 1.5 * iqr
    upper_fence = p75 + 1.5 * iqr

    outlier_count = sum(
        1 for value in values
        if value < lower_fence or value > upper_fence
    )

    return MetricStats(
        samples=len(values),
        mean=mean,
        median=median,
        stdev=stdev,
        cv=cv,
        minimum=min(values),
        p25=p25,
        p75=p75,
        p95=p95,
        maximum=max(values),
        iqr=iqr,
        outlier_count=outlier_count,
        outlier_fraction=outlier_count / len(values),
        lower_fence=lower_fence,
        upper_fence=upper_fence,
    )


def applicable_metrics(experiment: str) -> list[str]:
    if experiment == "size_sweep":
        return [
            "sign_ns",
            "sigverify_ns",
            "aggregate_ns",
            "aggverify_ns",
            "total_crypto_ns",
        ]
    if experiment == "sensitive_sweep":
        return [
            "sign_ns",
            "kem_encap_ns",
            "aead_encrypt_ns",
            "privacy_ns",
            "processing_and_signing_ns",
            "sigverify_ns",
            "aggregate_ns",
            "aggverify_ns",
            "total_crypto_ns",
        ]
    if experiment == "recovery_sweep":
        return [
            "kem_decap_ns",
            "aead_decrypt_ns",
            "recovery_ns",
        ]
    fail(f"Unknown experiment: {experiment}")


def validate_and_enrich_row(
    row: dict[str, str],
    line_number: int,
) -> dict[str, int | str | None]:
    if row["scheme"] != "BASR":
        fail(f"Line {line_number}: scheme is not BASR")
    if row["profile"] != EXPECTED_PROFILE:
        fail(
            f"Line {line_number}: expected profile full, "
            f"found {row['profile']!r}"
        )
    if row["correctness"].lower() != "true":
        fail(f"Line {line_number}: correctness is not true")

    experiment = row["experiment"]
    run = parse_required_int(row, "run")
    n = parse_required_int(row, "n")
    ns = parse_required_int(row, "ns")
    nr = parse_optional_int(row["nr"])
    report_size = parse_required_int(row, "report_size_bytes")
    accepted_count = parse_required_int(row, "accepted_count")

    if report_size != 1024:
        fail(
            f"Line {line_number}: expected 1024-byte reports, "
            f"found {report_size}"
        )
    if accepted_count != n:
        fail(
            f"Line {line_number}: accepted_count {accepted_count} "
            f"does not equal n {n}"
        )

    enriched: dict[str, int | str | None] = {
        "experiment": experiment,
        "run": run,
        "n": n,
        "ns": ns,
        "nr": nr,
    }

    for metric in BASE_METRICS:
        enriched[metric] = parse_optional_int(row[metric])

    if experiment in {"size_sweep", "sensitive_sweep"}:
        required = [
            "sign_ns",
            "kem_encap_ns",
            "aead_encrypt_ns",
            "privacy_ns",
            "sigverify_ns",
            "aggregate_ns",
            "aggverify_ns",
            "total_crypto_ns",
        ]
        for metric in required:
            if enriched[metric] is None:
                fail(
                    f"Line {line_number}: missing {metric}"
                )

        sign = int(enriched["sign_ns"])
        kem = int(enriched["kem_encap_ns"])
        aead = int(enriched["aead_encrypt_ns"])
        privacy = int(enriched["privacy_ns"])
        sigverify = int(enriched["sigverify_ns"])
        aggregate = int(enriched["aggregate_ns"])
        aggverify = int(enriched["aggverify_ns"])
        total = int(enriched["total_crypto_ns"])

        if any(
            value < 0
            for value in [
                sign,
                kem,
                aead,
                privacy,
                sigverify,
                aggregate,
                aggverify,
                total,
            ]
        ):
            fail(f"Line {line_number}: negative timing value")

        if privacy != kem + aead:
            fail(
                f"Line {line_number}: privacy formula mismatch"
            )

        expected_total = (
            sign
            + privacy
            + sigverify
            + aggregate
            + aggverify
        )
        if total != expected_total:
            fail(
                f"Line {line_number}: total crypto formula mismatch"
            )

        enriched["processing_and_signing_ns"] = sign + privacy

        if experiment == "size_sweep":
            if n not in SIZE_VALUES or ns != 0 or nr is not None:
                fail(
                    f"Line {line_number}: invalid size_sweep parameters"
                )
            if kem != 0 or aead != 0 or privacy != 0:
                fail(
                    f"Line {line_number}: size_sweep privacy must be zero"
                )
        else:
            if (
                n != 200
                or ns not in SENSITIVE_VALUES
                or nr is not None
            ):
                fail(
                    f"Line {line_number}: invalid sensitive_sweep parameters"
                )

    elif experiment == "recovery_sweep":
        if (
            n != 200
            or ns != 200
            or nr not in RECOVERY_VALUES
        ):
            fail(
                f"Line {line_number}: invalid recovery_sweep parameters"
            )

        kem_decap = enriched["kem_decap_ns"]
        aead_decrypt = enriched["aead_decrypt_ns"]
        recovery = enriched["recovery_ns"]

        if (
            kem_decap is None
            or aead_decrypt is None
            or recovery is None
        ):
            fail(
                f"Line {line_number}: missing recovery timing"
            )

        if (
            int(kem_decap) < 0
            or int(aead_decrypt) < 0
            or int(recovery) < 0
        ):
            fail(
                f"Line {line_number}: negative recovery timing"
            )

        if int(recovery) != int(kem_decap) + int(aead_decrypt):
            fail(
                f"Line {line_number}: recovery formula mismatch"
            )

        enriched["processing_and_signing_ns"] = None

        for metric in [
            "sign_ns",
            "kem_encap_ns",
            "aead_encrypt_ns",
            "privacy_ns",
            "sigverify_ns",
            "aggregate_ns",
            "aggverify_ns",
            "total_crypto_ns",
        ]:
            if enriched[metric] is not None:
                fail(
                    f"Line {line_number}: recovery row contains {metric}"
                )
    else:
        fail(
            f"Line {line_number}: unknown experiment {experiment!r}"
        )

    return enriched


def scenario_from_row(
    row: dict[str, int | str | None],
) -> Scenario:
    return Scenario(
        experiment=str(row["experiment"]),
        n=int(row["n"]),
        ns=int(row["ns"]),
        nr=(
            None
            if row["nr"] is None
            else int(row["nr"])
        ),
    )


def scenario_sort_key(scenario: Scenario) -> tuple[int, int]:
    order = {
        "size_sweep": 0,
        "sensitive_sweep": 1,
        "recovery_sweep": 2,
    }
    return order[scenario.experiment], scenario.x_value


def format_float(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:.6f}"


def write_csv(
    path: Path,
    header: list[str],
    rows: Iterable[list[object]],
) -> None:
    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def monotonicity_notes(
    stats_by_scenario_metric: dict[
        tuple[Scenario, str],
        MetricStats,
    ],
) -> list[str]:
    notes: list[str] = []

    checks = [
        (
            "size_sweep",
            "sign_ns",
            SIZE_VALUES,
        ),
        (
            "size_sweep",
            "sigverify_ns",
            SIZE_VALUES,
        ),
        (
            "size_sweep",
            "aggregate_ns",
            SIZE_VALUES,
        ),
        (
            "size_sweep",
            "aggverify_ns",
            SIZE_VALUES,
        ),
        (
            "sensitive_sweep",
            "privacy_ns",
            SENSITIVE_VALUES,
        ),
        (
            "sensitive_sweep",
            "processing_and_signing_ns",
            SENSITIVE_VALUES,
        ),
        (
            "recovery_sweep",
            "recovery_ns",
            RECOVERY_VALUES,
        ),
    ]

    for experiment, metric, x_values in checks:
        medians: list[tuple[int, float]] = []

        for x_value in x_values:
            matching = [
                (scenario, stats)
                for (scenario, metric_name), stats
                in stats_by_scenario_metric.items()
                if (
                    scenario.experiment == experiment
                    and scenario.x_value == x_value
                    and metric_name == metric
                )
            ]
            if len(matching) != 1:
                fail(
                    f"Could not uniquely locate {experiment}, "
                    f"x={x_value}, metric={metric}"
                )
            medians.append(
                (x_value, matching[0][1].median)
            )

        decreases = []
        for previous, current in zip(
            medians,
            medians[1:],
        ):
            if current[1] < previous[1]:
                relative_drop = (
                    previous[1] - current[1]
                ) / previous[1]
                decreases.append(
                    (
                        previous[0],
                        current[0],
                        relative_drop,
                    )
                )

        if not decreases:
            notes.append(
                f"MONOTONIC: {experiment}/{metric} "
                f"median is non-decreasing."
            )
        else:
            detail = "; ".join(
                f"{left}->{right}: "
                f"{drop * 100:.2f}% drop"
                for left, right, drop in decreases
            )
            notes.append(
                f"NON_MONOTONIC: {experiment}/{metric}: {detail}"
            )

    return notes


def main() -> int:
    if len(sys.argv) != 2:
        print(
            "Usage: analyze_basr_crypto_results.py "
            "<full-result-directory>",
            file=sys.stderr,
        )
        return 2

    result_dir = Path(sys.argv[1]).resolve()
    raw_path = result_dir / RAW_NAME
    metadata_path = result_dir / METADATA_NAME

    if not raw_path.is_file():
        fail(f"Raw CSV not found: {raw_path}")
    if not metadata_path.is_file():
        fail(f"Metadata file not found: {metadata_path}")

    metadata = read_metadata(metadata_path)

    if metadata.get("profile") != EXPECTED_PROFILE:
        fail(
            f"Expected profile={EXPECTED_PROFILE}, "
            f"found {metadata.get('profile')!r}"
        )
    if int(metadata.get("measurement_runs", "-1")) != EXPECTED_MEASUREMENTS:
        fail(
            "Metadata measurement_runs is not 30"
        )
    if int(metadata.get("report_size_bytes", "-1")) != 1024:
        fail(
            "Metadata report_size_bytes is not 1024"
        )

    with raw_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        reader = csv.DictReader(handle)
        rows = [
            validate_and_enrich_row(row, line_number)
            for line_number, row in enumerate(
                reader,
                start=2,
            )
        ]

    if len(rows) != EXPECTED_ROWS:
        fail(
            f"Expected {EXPECTED_ROWS} data rows, "
            f"found {len(rows)}"
        )

    grouped_rows: dict[
        Scenario,
        list[dict[str, int | str | None]],
    ] = defaultdict(list)

    for row in rows:
        grouped_rows[scenario_from_row(row)].append(row)

    expected_scenarios = (
        len(SIZE_VALUES)
        + len(SENSITIVE_VALUES)
        + len(RECOVERY_VALUES)
    )
    if len(grouped_rows) != expected_scenarios:
        fail(
            f"Expected {expected_scenarios} scenarios, "
            f"found {len(grouped_rows)}"
        )

    for scenario, scenario_rows in grouped_rows.items():
        runs = sorted(int(row["run"]) for row in scenario_rows)
        if runs != list(range(1, EXPECTED_MEASUREMENTS + 1)):
            fail(
                f"Scenario {scenario} has invalid run sequence: {runs}"
            )

    stats_by_scenario_metric: dict[
        tuple[Scenario, str],
        MetricStats,
    ] = {}

    summary_rows: list[list[object]] = []
    outlier_rows: list[list[object]] = []
    warnings: list[str] = []

    for scenario in sorted(
        grouped_rows,
        key=scenario_sort_key,
    ):
        scenario_rows = grouped_rows[scenario]

        for metric in applicable_metrics(
            scenario.experiment
        ):
            values = [
                float(row[metric])
                for row in scenario_rows
                if row[metric] is not None
            ]

            stats = compute_stats(values)
            stats_by_scenario_metric[
                (scenario, metric)
            ] = stats

            summary_rows.append([
                scenario.experiment,
                scenario.n,
                scenario.ns,
                "" if scenario.nr is None else scenario.nr,
                scenario.x_name,
                scenario.x_value,
                metric,
                stats.samples,
                format_float(stats.mean),
                format_float(stats.median),
                format_float(stats.stdev),
                format_float(stats.cv),
                format_float(stats.minimum),
                format_float(stats.p25),
                format_float(stats.p75),
                format_float(stats.p95),
                format_float(stats.maximum),
                format_float(stats.iqr),
                stats.outlier_count,
                format_float(stats.outlier_fraction),
            ])

            if stats.cv is not None and stats.cv > 0.20:
                warnings.append(
                    f"HIGH_CV: {scenario.experiment} "
                    f"x={scenario.x_value} {metric} "
                    f"CV={stats.cv:.4f}"
                )

            if stats.outlier_fraction > 0.10:
                warnings.append(
                    f"MANY_OUTLIERS: {scenario.experiment} "
                    f"x={scenario.x_value} {metric} "
                    f"outliers={stats.outlier_count}/"
                    f"{stats.samples}"
                )

            for row in scenario_rows:
                value = row[metric]
                assert value is not None
                numeric_value = float(value)

                if (
                    numeric_value < stats.lower_fence
                    or numeric_value > stats.upper_fence
                ):
                    outlier_rows.append([
                        scenario.experiment,
                        scenario.n,
                        scenario.ns,
                        (
                            ""
                            if scenario.nr is None
                            else scenario.nr
                        ),
                        row["run"],
                        metric,
                        int(numeric_value),
                        format_float(stats.p25),
                        format_float(stats.p75),
                        format_float(stats.iqr),
                        format_float(stats.lower_fence),
                        format_float(stats.upper_fence),
                    ])

    summary_path = (
        result_dir / "basr-crypto-summary-long.csv"
    )
    outlier_path = (
        result_dir / "basr-crypto-outliers.csv"
    )
    figure_path = (
        result_dir / "basr-crypto-figure-data.csv"
    )
    report_path = (
        result_dir / "basr-crypto-quality-report.txt"
    )
    checksum_path = (
        result_dir / "analysis-checksums.sha256"
    )

    write_csv(
        summary_path,
        SUMMARY_HEADER,
        summary_rows,
    )
    write_csv(
        outlier_path,
        OUTLIER_HEADER,
        outlier_rows,
    )

    figure_specs = [
        (
            "Fig.1",
            "size_sweep",
            "sign_ns",
            "BASR",
        ),
        (
            "Fig.2",
            "size_sweep",
            "sigverify_ns",
            "BASR",
        ),
        (
            "Fig.3",
            "size_sweep",
            "aggregate_ns",
            "BASR",
        ),
        (
            "Fig.4",
            "size_sweep",
            "aggverify_ns",
            "BASR",
        ),
        (
            "Fig.5",
            "sensitive_sweep",
            "privacy_ns",
            "BASR protection",
        ),
        (
            "Fig.6",
            "sensitive_sweep",
            "processing_and_signing_ns",
            "BASR protection and signing",
        ),
        (
            "Fig.7",
            "sensitive_sweep",
            "total_crypto_ns",
            "BASR",
        ),
        (
            "Fig.8",
            "recovery_sweep",
            "kem_decap_ns",
            "KEM decapsulation",
        ),
        (
            "Fig.8",
            "recovery_sweep",
            "aead_decrypt_ns",
            "AEAD decryption",
        ),
        (
            "Fig.8",
            "recovery_sweep",
            "recovery_ns",
            "Total recovery",
        ),
    ]

    figure_rows: list[list[object]] = []

    for (
        figure,
        experiment,
        metric,
        series,
    ) in figure_specs:
        matching = sorted(
            (
                (
                    scenario,
                    stats,
                )
                for (scenario, metric_name), stats
                in stats_by_scenario_metric.items()
                if (
                    scenario.experiment == experiment
                    and metric_name == metric
                )
            ),
            key=lambda item: item[0].x_value,
        )

        for scenario, stats in matching:
            figure_rows.append([
                figure,
                scenario.x_name,
                scenario.x_value,
                series,
                metric,
                stats.samples,
                f"{stats.mean / 1_000_000:.9f}",
                f"{stats.median / 1_000_000:.9f}",
                f"{stats.stdev / 1_000_000:.9f}",
                f"{stats.p25 / 1_000_000:.9f}",
                f"{stats.p75 / 1_000_000:.9f}",
                f"{stats.p95 / 1_000_000:.9f}",
                f"{stats.minimum / 1_000_000:.9f}",
                f"{stats.maximum / 1_000_000:.9f}",
                stats.outlier_count,
            ])

    write_csv(
        figure_path,
        FIGURE_HEADER,
        figure_rows,
    )

    monotonic_notes = monotonicity_notes(
        stats_by_scenario_metric
    )

    status = (
        "PASS"
        if not warnings
        else "PASS_WITH_WARNINGS"
    )

    report_lines = [
        "BASR cryptographic benchmark quality report",
        "==========================================",
        f"status={status}",
        f"result_directory={result_dir}",
        f"raw_sha256={sha256(raw_path)}",
        f"metadata_sha256={sha256(metadata_path)}",
        f"rows={len(rows)}",
        f"scenarios={len(grouped_rows)}",
        f"measurements_per_scenario={EXPECTED_MEASUREMENTS}",
        f"summary_rows={len(summary_rows)}",
        f"iqr_outlier_rows={len(outlier_rows)}",
        f"warning_count={len(warnings)}",
        "",
        "Hard validation",
        "---------------",
        "PASS: profile is full.",
        "PASS: 570 raw rows are present.",
        "PASS: all 19 scenarios are present.",
        "PASS: every scenario contains runs 1..30.",
        "PASS: all correctness flags are true.",
        "PASS: accepted_count equals n.",
        "PASS: privacy and total-time formulas are exact.",
        "PASS: recovery-time formula is exact.",
        "",
        "Monotonicity observations",
        "-------------------------",
        *monotonic_notes,
        "",
        "Warnings",
        "--------",
    ]

    if warnings:
        report_lines.extend(warnings)
    else:
        report_lines.append("None.")

    report_lines.extend([
        "",
        "Interpretation",
        "--------------",
        "IQR outliers are reported, not deleted.",
        "The summary contains both mean and median.",
        "Use the median and IQR for robust plotting unless the "
        "final methodology explicitly selects mean and standard deviation.",
        "A monotonicity warning alone does not invalidate the run; "
        "inspect its CV, IQR, and neighboring scenarios.",
        "",
        "Generated files",
        "---------------",
        summary_path.name,
        outlier_path.name,
        figure_path.name,
        report_path.name,
    ])

    report_path.write_text(
        "\n".join(report_lines) + "\n",
        encoding="utf-8",
    )

    generated = [
        summary_path,
        outlier_path,
        figure_path,
        report_path,
    ]

    checksum_lines = [
        f"{sha256(path)}  {path.name}"
        for path in generated
    ]
    checksum_path.write_text(
        "\n".join(checksum_lines) + "\n",
        encoding="utf-8",
    )

    print("BASR result analysis completed.")
    print(f"status={status}")
    print(f"raw_rows={len(rows)}")
    print(f"scenarios={len(grouped_rows)}")
    print(f"summary_rows={len(summary_rows)}")
    print(f"iqr_outlier_rows={len(outlier_rows)}")
    print(f"warnings={len(warnings)}")
    print(f"quality_report={report_path}")
    print(f"figure_data={figure_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            f"ANALYSIS FAILED: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(1)