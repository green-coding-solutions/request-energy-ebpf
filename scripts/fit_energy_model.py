#!/usr/bin/env python3
import argparse
import csv
import json
import math
import random


ENERGY_MODEL_SCALE = 1000.0


def parse_args():
    parser = argparse.ArgumentParser(description="Fit a direct energy model from collected PSYS intervals.")
    parser.add_argument("--input-csv", required=True, help="CSV emitted by http_energy --collect-csv.")
    parser.add_argument("--output-config", required=True, help="Path to write the fitted energy_model.conf.")
    parser.add_argument("--report-json", help="Optional path for metrics and coefficients as JSON.")
    parser.add_argument("--target-column", default="active_psys_uj",
                        choices=["active_psys_uj", "interval_psys_uj"],
                        help="Energy target used for fitting.")
    parser.add_argument("--train-fraction", type=float, default=0.8, help="Fraction of rows used for training.")
    parser.add_argument("--seed", type=int, default=7, help="Deterministic split seed.")
    parser.add_argument("--ridge", type=float, default=1e-9, help="Ridge regularization added to X^T X.")
    parser.add_argument("--psys-interval-ms", type=int, default=200,
                        help="psys_interval_ms written into the generated config.")
    return parser.parse_args()


def parse_freq_runtime(text):
    runtimes = {}
    text = (text or "").strip()
    if not text:
        return runtimes

    for chunk in text.split(";"):
        if not chunk:
            continue
        khz_text, runtime_text = chunk.split(":", 1)
        khz = int(khz_text)
        runtime_ns = float(runtime_text)
        runtimes[khz] = runtimes.get(khz, 0.0) + runtime_ns

    return runtimes


def load_rows(path, target_column):
    rows = []
    freq_keys = set()

    with open(path, newline="", encoding="utf-8") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            target = float(row[target_column])
            freq_runtime = parse_freq_runtime(row.get("freq_runtime_ns", ""))
            for khz in freq_runtime:
                freq_keys.add(khz)

            rows.append({
                "target": target,
                "freq_runtime": freq_runtime,
                "wakeup_penalty": float(row["wakeups"]),
                "cycles_weight": float(row["cycles"]),
                "instructions_weight": float(row["instructions"]),
                "cache_miss_weight": float(row["cache_misses"]),
                "migration_penalty": float(row["migrations"]),
            })

    return rows, sorted(freq_keys)


def build_feature_names(freq_keys):
    names = [f"freq_khz={khz}" for khz in freq_keys]
    names.extend([
        "wakeup_penalty",
        "cycles_weight",
        "instructions_weight",
        "cache_miss_weight",
        "migration_penalty",
    ])
    return names


def row_to_features(row, freq_keys):
    vector = [row["freq_runtime"].get(khz, 0.0) for khz in freq_keys]
    vector.extend([
        row["wakeup_penalty"],
        row["cycles_weight"],
        row["instructions_weight"],
        row["cache_miss_weight"],
        row["migration_penalty"],
    ])
    return vector


def split_rows(rows, train_fraction, seed):
    shuffled = list(rows)
    rng = random.Random(seed)
    rng.shuffle(shuffled)

    split = int(len(shuffled) * train_fraction)
    split = max(1, min(len(shuffled) - 1, split)) if len(shuffled) > 1 else len(shuffled)
    return shuffled[:split], shuffled[split:] if len(shuffled) > 1 else []


def solve_linear_system(matrix, rhs):
    n = len(rhs)
    a = [row[:] + [rhs_value] for row, rhs_value in zip(matrix, rhs)]

    for col in range(n):
        pivot = max(range(col, n), key=lambda row: abs(a[row][col]))
        if abs(a[pivot][col]) < 1e-18:
            continue
        if pivot != col:
            a[col], a[pivot] = a[pivot], a[col]

        pivot_value = a[col][col]
        for j in range(col, n + 1):
            a[col][j] /= pivot_value

        for row in range(n):
            if row == col:
                continue
            factor = a[row][col]
            if factor == 0.0:
                continue
            for j in range(col, n + 1):
                a[row][j] -= factor * a[col][j]

    return [a[i][n] for i in range(n)]


def fit_ridge_regression(rows, freq_keys, ridge):
    feature_count = len(freq_keys) + 5
    xtx = [[0.0 for _ in range(feature_count)] for _ in range(feature_count)]
    xty = [0.0 for _ in range(feature_count)]

    for row in rows:
        features = row_to_features(row, freq_keys)
        target = row["target"]

        for i in range(feature_count):
            xty[i] += features[i] * target
            for j in range(feature_count):
                xtx[i][j] += features[i] * features[j]

    for i in range(feature_count):
        xtx[i][i] += ridge

    coeffs = solve_linear_system(xtx, xty)
    return [max(0.0, coeff) for coeff in coeffs]


def predict(row, freq_keys, coeffs):
    features = row_to_features(row, freq_keys)
    return sum(value * coeff for value, coeff in zip(features, coeffs))


def evaluate(rows, freq_keys, coeffs):
    if not rows:
        return {
            "rows": 0,
            "mae_uj": 0.0,
            "rmse_uj": 0.0,
            "mape_pct": 0.0,
            "r2": 0.0,
        }

    abs_error = 0.0
    squared_error = 0.0
    pct_error_sum = 0.0
    pct_error_count = 0
    targets = [row["target"] for row in rows]
    target_mean = sum(targets) / len(targets)
    total_variance = sum((target - target_mean) ** 2 for target in targets)

    for row in rows:
        prediction = predict(row, freq_keys, coeffs)
        error = prediction - row["target"]
        abs_error += abs(error)
        squared_error += error * error
        if row["target"] > 0:
            pct_error_sum += abs(error) / row["target"]
            pct_error_count += 1

    mae = abs_error / len(rows)
    rmse = math.sqrt(squared_error / len(rows))
    mape = (pct_error_sum / pct_error_count * 100.0) if pct_error_count else 0.0
    r2 = 1.0 - (squared_error / total_variance) if total_variance > 0 else 0.0
    return {
        "rows": len(rows),
        "mae_uj": mae,
        "rmse_uj": rmse,
        "mape_pct": mape,
        "r2": r2,
    }


def runtime_weighted_average(freq_keys, coeffs, rows):
    total_runtime = 0.0
    total_weighted = 0.0
    for row in rows:
        for idx, khz in enumerate(freq_keys):
            runtime_ns = row["freq_runtime"].get(khz, 0.0)
            total_runtime += runtime_ns
            total_weighted += runtime_ns * coeffs[idx]
    if total_runtime <= 0.0:
        return 0.0
    return total_weighted / total_runtime


def write_config(path, freq_keys, coeffs, default_runtime_coeff, psys_interval_ms):
    wakeup_coeff = coeffs[len(freq_keys)]
    cycles_coeff = coeffs[len(freq_keys) + 1]
    instructions_coeff = coeffs[len(freq_keys) + 2]
    cache_miss_coeff = coeffs[len(freq_keys) + 3]
    migration_coeff = coeffs[len(freq_keys) + 4]

    lines = [
        "# Generated by scripts/fit_energy_model.py",
        "# In attribution_mode=model the coefficients are interpreted as direct",
        "# microjoule weights applied in-kernel.",
        "attribution_mode=model",
        f"default_multiplier={default_runtime_coeff:.9f}",
        f"wakeup_penalty={int(round(wakeup_coeff))}",
        f"cycles_weight={cycles_coeff:.9f}",
        f"instructions_weight={instructions_coeff:.9f}",
        f"cache_miss_weight={cache_miss_coeff:.9f}",
        f"migration_penalty={int(round(migration_coeff))}",
        "idle_power_uw=0",
        f"psys_interval_ms={psys_interval_ms}",
    ]

    for idx, khz in enumerate(freq_keys):
        lines.append(f"freq_khz={khz} {coeffs[idx]:.9f}")

    with open(path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
        fp.write("\n")


def main():
    args = parse_args()
    rows, freq_keys = load_rows(args.input_csv, args.target_column)
    if len(rows) < 2:
        raise SystemExit("Need at least two collected intervals to fit and evaluate a model.")

    train_rows, test_rows = split_rows(rows, args.train_fraction, args.seed)
    coeffs = fit_ridge_regression(train_rows, freq_keys, args.ridge)
    default_runtime_coeff = runtime_weighted_average(freq_keys, coeffs, train_rows)

    train_metrics = evaluate(train_rows, freq_keys, coeffs)
    test_metrics = evaluate(test_rows, freq_keys, coeffs)

    report = {
        "input_csv": args.input_csv,
        "target_column": args.target_column,
        "train_rows": train_metrics,
        "test_rows": test_metrics,
        "coefficients": {
            "default_multiplier": default_runtime_coeff,
            "freq_runtime_uj_per_ns": {
                str(khz): coeffs[idx] for idx, khz in enumerate(freq_keys)
            },
            "wakeup_penalty_uj": coeffs[len(freq_keys)],
            "cycles_weight_uj_per_count": coeffs[len(freq_keys) + 1],
            "instructions_weight_uj_per_count": coeffs[len(freq_keys) + 2],
            "cache_miss_weight_uj_per_count": coeffs[len(freq_keys) + 3],
            "migration_penalty_uj": coeffs[len(freq_keys) + 4],
        },
    }

    write_config(args.output_config, freq_keys, coeffs, default_runtime_coeff, args.psys_interval_ms)
    if args.report_json:
        with open(args.report_json, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2, sort_keys=True)
            fp.write("\n")

    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
