#!/usr/bin/env python3
"""Print the NWB fields needed by the browser demo fixture extractor.

This is intentionally read-only and emits JSON on stdout so it can be piped over
SSH without copying the source recording or creating files on the remote host.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import h5py
import numpy as np


def json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if hasattr(value, "tolist"):
        return value.tolist()
    return value


def describe(node: h5py.Group | h5py.Dataset) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "dataset" if isinstance(node, h5py.Dataset) else "group",
        "attrs": {key: json_value(value) for key, value in node.attrs.items()},
    }
    if isinstance(node, h5py.Dataset):
        result.update({"shape": list(node.shape), "dtype": str(node.dtype)})
    else:
        result["keys"] = sorted(node.keys())
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: inspect-nwb-demo-source.py SOURCE.nwb", file=sys.stderr)
        return 2
    with h5py.File(sys.argv[1], "r") as nwb:
        waveforms = nwb["processing/spike_waveforms"]
        waveform_details = {}
        for key in sorted(waveforms.keys()):
            dataset = waveforms[key]
            summary = describe(dataset)
            sampled = dataset[:: max(1, dataset.shape[0] // 2_000)]
            summary["sampled_quantiles"] = {
                str(percentile): float(np.percentile(sampled, percentile))
                for percentile in (0, 1, 50, 99, 100)
            }
            summary["first_waveform"] = [float(value) for value in dataset[0]]
            waveform_details[key] = summary
        result = {
            "source": sys.argv[1],
            "root_keys": sorted(nwb.keys()),
            "spike_waveforms": waveform_details,
            "acquisition": {
                key: describe(nwb["acquisition"][key]) for key in sorted(nwb["acquisition"].keys())
            },
            "processing": {
                key: describe(nwb["processing"][key]) for key in sorted(nwb["processing"].keys())
            },
        }
        if "units" in nwb:
            result["units"] = {
                key: describe(nwb["units"][key]) for key in sorted(nwb["units"].keys())
            }
        for candidate in (
            "acquisition/LFP/data",
            "processing/ecephys/LFP/ElectricalSeries/data",
            "processing/lfp/LFP/data",
            "acquisition/ElectricalSeries/data",
        ):
            if candidate in nwb:
                dataset = nwb[candidate]
                stride = max(1, dataset.shape[0] // 50_000)
                sampled = np.asarray(dataset[::stride], dtype=np.float64)
                result["lfp"] = {
                    "path": candidate,
                    **describe(dataset),
                    "parent_attrs": {
                        key: json_value(value) for key, value in dataset.parent.attrs.items()
                    },
                    "sample_stride": stride,
                    "sampled_quantiles": {
                        str(percentile): float(np.percentile(sampled, percentile))
                        for percentile in (0, 1, 50, 99, 100)
                    },
                    "channel_peak_to_peak": np.ptp(sampled, axis=0).astype(float).tolist(),
                }
                break
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
