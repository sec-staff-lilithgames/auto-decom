#!/usr/bin/env python3
#@category AutoDeDecompile
"""
Ghidra script that emits pseudo-C and assembly listings for the current program.
Arguments:
    1. Destination directory
    2. Base filename (without extension)
Outputs:
    <dest>/<base>.c
    <dest>/<base>.asm
"""

import os

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def ensure_directory(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _encode(text):
    if text is None:
        return b""
    if isinstance(text, bytes):
        return text
    return str(text).encode("utf-8", "replace")


def export_c(decompiler, monitor, program, destination):
    print("[export_decomp] writing C to {}".format(destination))
    with open(destination, "wb") as writer:
        function_manager = program.getFunctionManager()
        iterator = function_manager.getFunctions(True)
        while iterator.hasNext() and not monitor.isCancelled():
            function = iterator.next()
            result = decompiler.decompileFunction(function, 120, monitor)
            if result and result.decompileCompleted():
                writer.write(_encode(result.getDecompiledFunction().getC()))
                writer.write(b"\n\n")
            else:
                msg = "/* Failed to decompile {} */\n\n".format(function.getName())
                writer.write(_encode(msg))


def export_asm(program, monitor, destination):
    listing = program.getListing()
    print("[export_decomp] writing ASM to {}".format(destination))
    with open(destination, "wb") as writer:
        instructions = listing.getInstructions(True)
        while instructions.hasNext() and not monitor.isCancelled():
            instruction = instructions.next()
            address = instruction.getAddress()
            line = "{}: {}\n".format(address, instruction)
            writer.write(_encode(line))


def main():
    args = getScriptArgs()
    if len(args) < 2:
        print("[export_decomp] expected <output_dir> <base_name>")
        return

    output_dir = args[0]
    base_name = args[1]
    ensure_directory(output_dir)

    monitor = ConsoleTaskMonitor()
    program = currentProgram

    decompiler = DecompInterface()
    if not decompiler.openProgram(program):
        print("[export_decomp] failed to open program in decompiler")
        return

    try:
        export_c_path = os.path.join(output_dir, "{}.c".format(base_name))
        export_asm_path = os.path.join(output_dir, "{}.asm".format(base_name))
        export_c(decompiler, monitor, program, export_c_path)
        export_asm(program, monitor, export_asm_path)
    finally:
        decompiler.dispose()


main()
