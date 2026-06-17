#!/usr/bin/env python3
import struct
import sys
from pathlib import Path
from collections import Counter

KNOWN = {
    0x6CA300: "managed_invoke_adapter",
    0x6BDA80: "managed_materialize_collection",
    0x6BD760: "managed_invoke_indexed_adapter",
    0x6BCB50: "release_managed_wrapper_slot",
    0x6BCBB0: "move_assign_managed_wrapper_slot",
    0x6BCBF0: "init_or_reset_managed_wrapper",
    0x6BDB90: "managed_collection_enumerator_advance",
    0x6BF490: "managed_value_equals_adapter",
    0x6CA480: "managed_invoke_with_result_check",
    0x6BD8C0: "managed_enumerator_get_current",
    0x6BD6B0: "managed_get_property_value",
    0x6C2CE0: "monitor_authnative_presence",
    0x6C27C0: "monitor_two_auth_delegate_targets",
    0x6C31E0: "find_managed_item_by_stored_value",
    0x6C3390: "find_runtime_and_stored_matches",
    0x6C9980: "refresh_collection_count_watchers",
    0x6C3FB0: "classify_api_route",
    0x6CA460: "managed_invoke_member_no_args",
    0x6CA620: "managed_push_object_wrapper",
    0x6CA630: "managed_push_result_wrapper",
    0x6C20C0: "managed_get_count",
    0x6C1CC0: "managed_compare_strings",
    0x74B650: "string_builder_append",
    0x130100: "shared_ptr_release",
    0x380139: "VM_CONTINUE",
    0x380140: "VM_BRANCH",
    0x380040: "VM_RETURN",
}

REGIONS = {
    "monitor_two_auth_delegate_targets": (0x4BA00C, 0x4C1BFD),
    "monitor_find_authnative": (0x53A1B6, 0x53EE72),
    "route_classifier": (0x55A13A, 0x563709),
}


def lift_region(binary, start, end):
    region = binary[start:end]
    calls = []
    i = 0
    while i < len(region) - 5:
        if region[i] == 0x80 and region[i + 1] == 0x00:
            addr = struct.unpack_from("<I", region, i + 2)[0]
            name = KNOWN.get(addr, f"sub_{addr:X}")
            calls.append((start + i, addr, name))
            i += 6
        else:
            i += 1
    return calls


def main():
    binary_path = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).parent.parent.parent / "AuthNative.so")
    binary = Path(binary_path).read_bytes()

    for region_name, (start, end) in REGIONS.items():
        calls = lift_region(binary, start, end)
        real = [c for c in calls if not c[2].startswith("VM_")]
        vm = [c for c in calls if c[2].startswith("VM_")]

        print(f"// {region_name} ({end-start} bytes)")
        print(f"// {len(real)} calls, {len(vm)} vm ops")
        for off, addr, name in calls:
            if name.startswith("VM_"):
                continue
            print(f"  0x{off:06X}: {name}")
        print()


if __name__ == "__main__":
    main()
