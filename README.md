# IDA Domain MCP Server
A lightweight MCP server which allows AI agents to preform reverse engineering tasks headlessly on IDA database files.

https://github.com/user-attachments/assets/a3554b99-464b-4a92-a867-3cef49f1ac82

## About
This project had two goals:
* Help me better understand and learn how MCP works and how agents can use it
* Allow for headless "vibe" reverse engineering utilizing Hexrays' powerful disassembler and decompiler.

This MCP server uses [FastMCP](https://fastmcp.wiki/en/v2/getting-started/welcome).
I recommend reading about the [IDA Domain API](https://ida-domain.docs.hex-rays.com/) so you can understand it's purpose and how it might fit into your projects.

## Features
Currently none of the MCPs tools modify the database. 
Actions supported:

* Database opening, closing, and displaying metadata
* Listing all segments
* Listing all strings
* Reading bytes
* All Xrefs calls/reads/writes
* Disassemble single/range
* Decompile to pseudocode

## Notes
* *You **must** have the `IDADIR` environment variable is set. This is a requirement for the IDA domain API:
* Depending on how your AI agent is sandboxed, you may need to set the IDAUSR environment variable for the user. This is because the domain API will try to write to `~/.idapro/ida.reg`. If your sandbox doesn't allow writing this will fail.
* In addition, you must ensure that the directory wit hthe .i64 database is readable and **writeable**. 

You need to add an MCP server:<br>

OpenAI codex:<br>
Open the ~/.codex/config.toml
```
[mcp_servers.ida_domain_mcp]
command = "python3"
args = ["ida_domain_mcp.py"]

[mcp_servers.dwu_ida_domain.env]
IDADIR = "/home/mike/ida-pro-9.1"
IDAUSR = "/tmp/idauser"
```
