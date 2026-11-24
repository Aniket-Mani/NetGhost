import platform
import subprocess


def get_default_route() -> dict:
    """
    Retrieve the system's default gateway and interface.
    Supports macOS and Linux.
    """
    system = platform.system()
    commands = {
        "Darwin": ["route", "-n", "get", "default"],
        "Linux": ["ip", "route", "show", "default"],
    }
    command = commands.get(system)

    if command is None:
        return {
            "gateway": None,
            "interface": None,
            "error": f"Unsupported platform: {system}",
        }

    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=3,check=False,
        )
        if result.returncode !=0:
            return {
                "gateway": None,
                "interface": None,
                "error": result.stderr.strip() or "Route command failed",
            }
        gateway = None
        interface = None

        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) < 2:
                continue

            if system == "Darwin":
                if parts[0] == "gateway:":
                    gateway = parts[1]
                elif parts[0] == "interface:":
                    interface = parts[1]

            elif system == "Linux" and parts[0] == "default":
                for index, part in enumerate(parts[:-1]):
                    if part == "via":
                        gateway = parts[index + 1]
                    elif part == "dev":
                        interface = parts[index + 1]
                break

        return {
            "gateway": gateway,
            "interface": interface,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "gateway": None,
            "interface": None,
            "error": "Default route lookup timed out",
        }

    except OSError as exc:
        return {
            "gateway": None,
            "interface": None,
            "error": str(exc),
        }