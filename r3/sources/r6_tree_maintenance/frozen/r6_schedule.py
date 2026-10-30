#!/usr/bin/env python3
"""Frozen serial R6 schedule shared by supervisor and tests."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

FORMAL_SEEDS = (2026103001, 2026103002, 2026103003, 2026103004, 2026103005)
PILOT_SEED = 2026103099


@dataclass(frozen=True)
class Cell:
    phase: str
    depth: int
    seed: int


def cells() -> tuple[Cell, ...]:
    # Pilot is completed evidence and must never be repeated by formal execution.
    return tuple(Cell("formal", depth, seed) for depth in (16, 20) for seed in FORMAL_SEEDS)


def execute(executor: Callable[[Cell], None]) -> None:
    """Execute exactly once in order; exceptions stop without retry."""
    for cell in cells():
        executor(cell)


def main() -> None:
    for cell in cells():
        print(f"{cell.phase}\t{cell.depth}\t{cell.seed}")


if __name__ == "__main__":
    main()

