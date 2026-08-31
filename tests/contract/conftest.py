from pathlib import Path


def pytest_sessionstart() -> None:
    sha = (Path(__file__).parent / "testdata" / "HUB_SHA").read_text().strip()
    print(f"SYNC: fixtures vendored from rootcause-embassy commit {sha}")
