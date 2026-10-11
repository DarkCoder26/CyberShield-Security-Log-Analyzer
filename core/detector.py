
import pandas as pd


SENSITIVE_PATHS = (
    "/.env",
    "/.git",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/admin",
)


def detect_events(
    df: pd.DataFrame,
    failed_threshold: int = 5,
    burst_threshold: int = 30,
) -> pd.DataFrame:
    """
    Apply defensive log-detection rules.

    Risk scores are heuristic investigation priorities, not
    probabilities that an attack has occurred.
    """
    output_columns = list(df.columns) + [
        "severity",
        "risk_score",
        "reason",
    ]

    if df.empty:
        return pd.DataFrame(columns=output_columns)

    data = df.copy()
    data["timestamp"] = pd.to_datetime(
        data["timestamp"], utc=True, errors="coerce"
    )
    data = data.dropna(subset=["timestamp"]).reset_index(drop=True)

    if data.empty:
        return pd.DataFrame(columns=output_columns)

    failed_threshold = max(1, int(failed_threshold))
    burst_threshold = max(1, int(burst_threshold))

    reasons_by_row = {i: [] for i in data.index}
    scores_by_row = {i: 0 for i in data.index}

    def flag(indices, points, reason):
        for idx in indices:
            reasons_by_row[idx].append(reason)
            scores_by_row[idx] += points

    # Rule 1: repeated 401/403 responses from an IP.
    auth_failures = data[data["status"].isin([401, 403])]

    failed_counts = auth_failures.groupby("ip").size()
    repeated_ips = set(
        failed_counts[failed_counts >= failed_threshold].index
    )

    for ip in repeated_ips:
        indices = auth_failures.index[
            auth_failures["ip"] == ip
        ].tolist()

        count = int(failed_counts[ip])
        flag(
            indices,
            35,
            f"Repeated authentication/authorization failures "
            f"({count} from this IP; threshold {failed_threshold})",
        )

    # Rule 2: requests to sensitive paths.
    for idx, row in data.iterrows():
        path = str(row["path"]).lower().split("?", 1)[0]

        if any(
            path == sensitive
            or path.startswith(sensitive + "/")
            for sensitive in SENSITIVE_PATHS
        ):
            flag(
                [idx],
                25,
                "Request to a sensitive path",
            )

    # Rule 3: rolling one-minute request volume per IP.
    # A two-pointer window avoids checking every row against every row.
    for ip, group in data.groupby("ip", sort=False):
        ordered = group.sort_values("timestamp")
        indices = ordered.index.tolist()
        times = ordered["timestamp"].tolist()

        left = 0

        for right in range(len(indices)):
            while (
                left <= right
                and times[right] - times[left]
                >= pd.Timedelta(minutes=1)
            ):
                left += 1

            window_count = right - left + 1

            if window_count >= burst_threshold:
                window_indices = indices[left:right + 1]
                flag(
                    window_indices,
                    40,
                    f"High request volume ({window_count} requests "
                    f"in a rolling minute; threshold {burst_threshold})",
                )

    # Create one output row per event, combining overlapping rules.
    findings = []

    for idx, row in data.iterrows():
        reasons = reasons_by_row[idx]

        if not reasons:
            continue

        score = min(scores_by_row[idx], 100)

        if score >= 60:
            severity = "High"
        elif score >= 30:
            severity = "Medium"
        else:
            severity = "Low"

        event = row.to_dict()
        event["severity"] = severity
        event["risk_score"] = score
        event["reason"] = "; ".join(dict.fromkeys(reasons))
        findings.append(event)

    if not findings:
        return pd.DataFrame(columns=output_columns)

    result = pd.DataFrame(findings)
    result["_severity_order"] = result["severity"].map({
        "High": 0,
        "Medium": 1,
        "Low": 2,
    })

    return (
        result.sort_values(
            ["_severity_order", "risk_score", "timestamp"],
            ascending=[True, False, False],
        )
        .drop(columns="_severity_order")
        .reset_index(drop=True)
    )
