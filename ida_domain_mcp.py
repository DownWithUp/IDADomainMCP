#!/usr/bin/env python3
"""Small MCP server for DWU IDA Domain helper tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from dataclasses import asdict

mcp = FastMCP("DWU IDA Domain MCP")

working_db: Any | None = None


def get_database_class() -> Any:
    try:
        from ida_domain import Database
    except ImportError as exc:
        raise RuntimeError(
            "Unable to load ida_domain. Make sure IDA 9.0 or newer is installed "
            "and IDADIR points at the active IDA installation."
        ) from exc

    return Database


@mcp.tool()
def open_database(database_path: str) -> bool:
    """Open an IDA database with the IDA domain API.

    Use this when the caller asks or needs to start working on a new IDA database. 
    This will load the database as the current working database. 
    Before running other tools the database must be opened with this function. 
    Returns True if the database was successfully opened.
    """
    global working_db

    Database = get_database_class()
    working_db = Database.open(path=database_path, save_on_close=False)
    return True


@mcp.tool()
def close_database(save_changes: bool = True) -> bool:
    """Closes the current working database.
    
    Use this tool when the caller wants to open a new database and a current working database is already open.
    Use this tool when the caller wants to save a database. Default action is to save changes, but can
    be called with false so that changes are not saved.
    """
    global working_db

    if working_db is None:
        raise ToolError("No database is currently open.")

    working_db.close(save=save_changes)
    working_db = None
    return True


def format_address(value: int) -> str:
    return f"0x{value:016x}"


def function_name(db: object, func: object) -> str:
    return db.functions.get_name(func) or "<unnamed>"

def parse_address(value: int | str | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value

    try:
        return int(value, 0)
    except ValueError as exc:
        raise ToolError(f"Invalid function_start_ea: {value!r}") from exc


@mcp.tool()
def list_functions(include_details: bool = False) -> dict[str, Any]:
    """Lists all the functions in the working database.

    Use this tool when the caller wants list all the functions within the working database.
    Set include_details to true to include each function start address, end address, size, and name.
    """
    if working_db is None:
        raise ToolError("No database is currently open.")

    functions = sorted(working_db.functions.get_all(), key=lambda func: func.start_ea)
    details = []

    if include_details:
        for func in functions:
            start_ea = func.start_ea
            end_ea = func.end_ea
            details.append(
                {
                    "name": function_name(working_db, func),
                    "start": format_address(start_ea),
                    "end": format_address(end_ea),
                    "size": max(0, end_ea - start_ea),
                }
            )

    return {"count": len(functions), "functions": details}


@mcp.tool()
def decompile_function(
    function_name: str | None = None,
    function_start_ea: str | None = None,
) -> list[str]:
    """Decompile a function based on name or effective address (ea).

    Use this tool when the caller wants decompile a specific function within the working database.
    Use the function_name parameter to specify the name of the function to decompile. 
    Use the function_start_ea parameter to specify the start EA/address of the function to decompile.
    This function returns a list of strings which is the decompiled pseudocode of the specified function.
    """
    
    if working_db is None:
        raise ToolError("No database is currently open.")
    
    target_ea = parse_address(function_start_ea)
    if function_name is None and target_ea is None:
        raise ToolError("At least one argument must be present.")

    functions = sorted(working_db.functions.get_all(), key=lambda func: func.start_ea)

    if function_name:
        target = next(
            (func for func in functions if working_db.functions.get_name(func) == function_name),
            None,
        )
        if target is None:
            raise ToolError(f"Function was not found: {function_name}")
    else:
        target = next(
            (func for func in functions if func.start_ea == target_ea),
            None,
        )
        if target is None:
            raise ToolError(f"Function was not found at address: 0x{target_ea:x}")


    try:
        pseudocode = working_db.functions.get_pseudocode(target)
    except Exception as error:
        raise ToolError("Failed to decompile the target function.") from error

    return [str(line) for line in pseudocode.to_text()]

@mcp.tool()
def get_disassembly(effective_address: str) -> str:
    """Returns a single instruction at the effective address.

    Use this tool when the caller wants to disassembly or view the underlying assembly instruction
    at a specific address.
    """
    if working_db is None:
        raise ToolError("No database is currently open.")
    
    return working_db.instructions.get_disassembly(working_db.instructions.get_at(parse_address(effective_address)))

@mcp.tool()
def get_disassembly_range(start_effective_address: str, end_effective_address: str) -> dict[str, Any]:
    """Returns the instructions starting at the effective address and ending at the ending effective address.

    Use this tool when the caller wants to disassembly or view a range of underlying assembly instructions
    at a specific address.
    """
    if working_db is None:
        raise ToolError("No database is currently open.")
    
    out = []
    for i in working_db.instructions.get_between(parse_address(start_effective_address), parse_address(end_effective_address)):
        out.append(working_db.instructions.get_disassembly(i))
    return {"count": len(out), "disassembly": out}

@mcp.tool() 
def get_cross_references_from_address(effective_address: str) -> dict[str, Any]:
    """Returns all cross references (xrefs) from the the effective address.

    Use this tool when the caller wants to find all the related cross references (xrefs) that 
    are from an address. This will return xrefs that are all types of accesses (data reads, data writes, and calls).
    The "type" return value is the type of xref. Here are the following meanings:
        CALL_FAR : Call Far - creates a function at referenced location
        CALL_NEAR : Call Near - creates a function at referenced location
        INFORMATIONAL : Informational reference
        JUMP_FAR : Jump Far
        JUMP_NEAR : Jump Near
        OFFSET : Offset reference or OFFSET flag set
        ORDINARY_FLOW : Ordinary flow to next instruction
        READ : Read access
        SYMBOLIC : Reference to enum member (symbolic constant)
        TEXT : Text (for forced operands only)
        UNKNOWN : Unknown
        USER_SPECIFIED : User specified (obsolete)
        WRITE : Write access
    """
    if working_db is None:
        raise ToolError("No database is currently open.")
    
    out = []
    for r in working_db.xrefs.from_ea(parse_address(effective_address)):
        out.append(
            {
                "from_ea": format_address(r.from_ea),
                "to_ea": format_address(r.to_ea),
                "is_code": r.is_code,
                "type": r.type
            }
        )
    return {"count": len(out), "xrefs": out}

@mcp.tool() 
def get_cross_references_to_address(effective_address: str) -> dict[str, Any]:
    """Returns all cross references (xrefs) to the the effective address.

    Use this tool when the caller wants to find all the related cross references (xrefs) that 
    are to an address. This will return xrefs that are all types of accesses (data reads, data writes, and calls).   
    The "type" return value is the type of xref. Here are the following meanings:
        CALL_FAR : Call Far - creates a function at referenced location
        CALL_NEAR : Call Near - creates a function at referenced location
        INFORMATIONAL : Informational reference
        JUMP_FAR : Jump Far
        JUMP_NEAR : Jump Near
        OFFSET : Offset reference or OFFSET flag set
        ORDINARY_FLOW : Ordinary flow to next instruction
        READ : Read access
        SYMBOLIC : Reference to enum member (symbolic constant)
        TEXT : Text (for forced operands only)
        UNKNOWN : Unknown
        USER_SPECIFIED : User specified (obsolete)
        WRITE : Write access
    """
    if working_db is None:
        raise ToolError("No database is currently open.")
    
    out = []
    for r in working_db.xrefs.to_ea(parse_address(effective_address)):
        out.append(
            {
                "from_ea": format_address(r.from_ea),
                "to_ea": format_address(r.to_ea),
                "is_code": r.is_code,
                "type": r.type
            }
        )
    return {"count": len(out), "xrefs": out}

@mcp.tool()
def get_bytes_at(effective_address: str, count: int) -> bytes | None:
    """Returns the bytes found at the effective address. The number of bytes returned is based on the count argument.

    Use this tool when the caller wants to get the raw bytes at an address.
    """
    if working_db is None:
        raise ToolError("No database is currently open.")

    out = working_db.bytes.get_bytes_at(parse_address(effective_address), count)
    return out

@mcp.tool()
def get_all_segments() -> list[str]:
    """Returns the all the segments (sometimes misunderstood as sections) within the database/underlying binary.

    Use this tool when the caller wants to know about the overall binary structure or information about all, or some, of the 
    segments/sections within the underlying binary.
    """
    if working_db is None:
        raise ToolError("No database is currently open.")
    

    details = []
    for s in working_db.segments.get_all():
        details.append(
            {
                "name": s.name,
                "start": s.start_ea,
                "end": s.end_ea,
                "size": s.size(),
            }
        )

    return {"count": len(details), "segments": details}
    
@mcp.tool()
def get_all_strings(decode_utf8: bool=True) -> dict[str, Any]:
    """Returns all the strings and their addresses found in the database/underlying binary. 

    Use this tool when the caller wants to know about any C strings within the database/binary. This tool always rebuilds the strings table 
    so on large binaries it may take a moment. By default the contents of all strings are decoded as UTF-8
    """
    if working_db is None:
        raise ToolError("No database is currently open.")
    
    all_strings = []
    working_db.strings.rebuild()
    for s in working_db.strings.get_all():
        all_strings.append(
            {"contents": s.contents.decode('utf-8') if decode_utf8 else s.contents, "address": s.address}
        )

    return {"count": len(all_strings), "strings": all_strings}


@mcp.tool()
def get_database_info() -> dict:
    """Returns information about the database and the underlying binary the database was originally created from.

    Use this tool when the caller wants information about the database or the original binary file.
    The following data is returned about the underlying binary the working database was created with: 
    path, module, base address, file size, md5 hash, sha256 hash, crc32, architecture, bitness, format, 
    load time, compiler information, and execution mode. 
    """
    if working_db is None:
        raise ToolError("No database is currently open.")

    metadata = asdict(working_db.metadata)
    return metadata


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
