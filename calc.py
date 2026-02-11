import struct
import sys
import argparse

def find_rop_combinations(target_hex, initial_hex="0x0"):
    try:
        target = int(target_hex, 16)
        initial = int(initial_hex, 16)
    except ValueError:
        print("[-] Error: Use hex format (e.g., 0x4B00)")
        return

    bad_chars = [0x00, 0x0a, 0x0d, 0x20]

    # Delta logic (handles 32-bit wrap-around)
    delta = (target - initial) & 0xFFFFFFFF

    def format_hex(val):
        return "0x{:08x}".format(val & 0xFFFFFFFF)

    def check_safe(val):
        bytes_val = struct.pack("<I", val & 0xFFFFFFFF)
        return "[!!!!]" if any(b in bad_chars for b in bytes_val) else "[SAFE]"

    # We now include your 'Initial' as the primary base
    bases = [initial, 0xFFFFFFFF, 0x55555555, 0x22222222, 0x77777777, 0x44444444, 0x11111111]
    # Remove duplicates if initial is one of the defaults
    bases = list(dict.fromkeys(bases))

    print(f"\n[+] ROP Calculator | Target: {format_hex(target)} | Initial: {format_hex(initial)}")
    print(f"Required Delta: {format_hex(delta)}")
    print("=" * 78)
    print(f"{'Type':<8} | {'Value A':<11} (Stat) | {'Value B':<11} (Stat)")
    print("=" * 78)

    # --- SINGLE OPERAND SECTION (The Fix) ---
    pop_for_not = (~target) & 0xFFFFFFFF
    pop_for_neg = (0x100000000 - target) & 0xFFFFFFFF
    print(f"{'NOT':<8} | {format_hex(pop_for_not):<11} {check_safe(pop_for_not)} | {format_hex(target):<11} (Targeted)")
    print(f"{'NEG':<8} | {format_hex(pop_for_neg):<11} {check_safe(pop_for_neg)} | {format_hex(target):<11} (Targeted)")
    print("-" * 82)

    # --- XOR SECTION ---
    for base in bases:
        val_b = delta ^ base if base == initial else (target ^ base)
        label = "(Init)" if base == initial else check_safe(base)
        print(f"{'XOR':<8} | {format_hex(base):<11} {label:<6} | {format_hex(val_b):<11} {check_safe(val_b)}")
    print("-" * 78)

    # --- ADD SECTION ---
    for base in bases:
        # If using Initial, we need: Initial + ValB = Target
        val_b = (target - base) & 0xFFFFFFFF
        label = "(Init)" if base == initial else check_safe(base)
        print(f"{'ADD':<8} | {format_hex(base):<11} {label:<6} | {format_hex(val_b):<11} {check_safe(val_b)}")
    print("-" * 78)

    # --- SUB SECTION ---
    for base in bases:
        # If using Initial, we need: Initial - ValB = Target
        val_b = (base - target) & 0xFFFFFFFF
        label = "(Init)" if base == initial else check_safe(base)
        print(f"{'SUB':<8} | {format_hex(base):<11} {label:<6} | {format_hex(val_b):<11} {check_safe(val_b)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSED ROP Math Helper")
    parser.add_argument("target", help="Target hex (e.g. 0x00000123)")
    parser.add_argument("initial", nargs="?", default="0x0", help="Current reg value")
    args = parser.parse_args()
    find_rop_combinations(args.target, args.initial)
