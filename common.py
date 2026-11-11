
import json
import os
from datetime import datetime, timezone


def finding(check, resource, severity, issue, fix):
    return {
        "check": check,
        "resource": resource,
        "severity": severity,
        "issue": issue,
        "recommendation": fix
    }


def save_report(findings, outdir="reports"):
    os.makedirs(outdir, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime(
        "%Y%m%d_%H%M%S"
    )

    path = f"{outdir}/audit_{ts}.json"

    with open(path, "w") as f:
        json.dump(
            {
                "generated": ts,
                "total": len(findings),
                "findings": findings
            },
            f,
            indent=2
        )

    return path
    
