"""
CSePS Entry Point
=================
Usage:
  python main.py server     # Run the FastAPI server (port 8000)
  python main.py scenarios  # Run scenario demo
  python main.py tests      # Run pytest
"""

import sys


def run_server():
    import uvicorn

    uvicorn.run("cseps.server:app", host="0.0.0.0", port=8000, reload=False)


def run_scenarios():
    import asyncio
    import scenarios

    asyncio.run(scenarios.main())


def run_tests():
    import pytest

    sys.exit(pytest.main(["-v", "tests/"]))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "scenarios"
    if cmd == "server":
        run_server()
    elif cmd == "scenarios":
        run_scenarios()
    elif cmd == "tests":
        run_tests()
    else:
        print("Usage: python main.py [server|scenarios|tests]")
