"""Render the synthetic attendance board used as private site evidence.

**Fixture material, not production code.**  Nothing under ``src`` imports this;
it exists so that the one piece of binary demo evidence in the repository is
*reproducible* rather than an opaque blob somebody once made.  Run it and the
same octets come back.

What it draws is a site's end-of-day attendance board: the site, the day, and
one worker's in and out times.  It is deliberately synthetic and deliberately
dull -- no real person, no real premises, no photograph of anybody.  The
privacy claim MUSTER makes is about *raw evidence staying at the source*, and
demonstrating it with somebody's actual CCTV would be an odd way to make the
point.

It is a PNG written by hand from zlib and a 5x7 bitmap font, because a fixture
generator that needed an imaging library would be a dependency the agent
distribution does not otherwise have -- and would put a decoder for arbitrary
image formats into the build of a process that reads private material.

    python packages/muster-agents/fixtures/render_attendance_board.py
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

#  A 5x7 bitmap font, one string of five hex-free rows per glyph.  Only the
#  characters the board needs: an alphabet nobody has to maintain.
GLYPHS: dict[str, tuple[str, ...]] = {
    "A": (".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"),
    "B": ("####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."),
    "C": (".###.", "#...#", "#....", "#....", "#....", "#...#", ".###."),
    "D": ("####.", "#...#", "#...#", "#...#", "#...#", "#...#", "####."),
    "E": ("#####", "#....", "#....", "####.", "#....", "#....", "#####"),
    "F": ("#####", "#....", "#....", "####.", "#....", "#....", "#...."),
    "G": (".###.", "#...#", "#....", "#.###", "#...#", "#...#", ".###."),
    "H": ("#...#", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"),
    "I": ("#####", "..#..", "..#..", "..#..", "..#..", "..#..", "#####"),
    "J": ("...##", "....#", "....#", "....#", "#...#", "#...#", ".###."),
    "K": ("#...#", "#..#.", "#.#..", "##...", "#.#..", "#..#.", "#...#"),
    "L": ("#....", "#....", "#....", "#....", "#....", "#....", "#####"),
    "M": ("#...#", "##.##", "#.#.#", "#...#", "#...#", "#...#", "#...#"),
    "N": ("#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#", "#...#"),
    "O": (".###.", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."),
    "P": ("####.", "#...#", "#...#", "####.", "#....", "#....", "#...."),
    "Q": (".###.", "#...#", "#...#", "#...#", "#.#.#", "#..#.", ".##.#"),
    "R": ("####.", "#...#", "#...#", "####.", "#.#..", "#..#.", "#...#"),
    "S": (".####", "#....", "#....", ".###.", "....#", "....#", "####."),
    "T": ("#####", "..#..", "..#..", "..#..", "..#..", "..#..", "..#.."),
    "U": ("#...#", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."),
    "V": ("#...#", "#...#", "#...#", "#...#", "#...#", ".#.#.", "..#.."),
    "W": ("#...#", "#...#", "#...#", "#...#", "#.#.#", "##.##", "#...#"),
    "X": ("#...#", "#...#", ".#.#.", "..#..", ".#.#.", "#...#", "#...#"),
    "Y": ("#...#", "#...#", ".#.#.", "..#..", "..#..", "..#..", "..#.."),
    "Z": ("#####", "....#", "...#.", "..#..", ".#...", "#....", "#####"),
    "0": (".###.", "#...#", "#..##", "#.#.#", "##..#", "#...#", ".###."),
    "1": ("..#..", ".##..", "..#..", "..#..", "..#..", "..#..", ".###."),
    "2": (".###.", "#...#", "....#", "...#.", "..#..", ".#...", "#####"),
    "3": ("#####", "...#.", "..#..", "...#.", "....#", "#...#", ".###."),
    "4": ("...#.", "..##.", ".#.#.", "#..#.", "#####", "...#.", "...#."),
    "5": ("#####", "#....", "####.", "....#", "....#", "#...#", ".###."),
    "6": ("..##.", ".#...", "#....", "####.", "#...#", "#...#", ".###."),
    "7": ("#####", "....#", "...#.", "..#..", ".#...", ".#...", ".#..."),
    "8": (".###.", "#...#", "#...#", ".###.", "#...#", "#...#", ".###."),
    "9": (".###.", "#...#", "#...#", ".####", "....#", "...#.", ".##.."),
    ":": (".....", "..#..", "..#..", ".....", "..#..", "..#..", "....."),
    "-": (".....", ".....", ".....", "#####", ".....", ".....", "....."),
    ".": (".....", ".....", ".....", ".....", ".....", "..#..", "..#.."),
    "/": ("....#", "...#.", "...#.", "..#..", ".#...", ".#...", "#...."),
    " ": (".....", ".....", ".....", ".....", ".....", ".....", "....."),
}

GLYPH_WIDTH = 5
GLYPH_HEIGHT = 7
#  Three device pixels per font pixel: large enough to read on a projector,
#  small enough that the file stays a few kilobytes.
SCALE = 3
MARGIN = 12
LINE_GAP = 6

INK = (16, 24, 32)
PAPER = (244, 244, 238)
RULE = (150, 160, 168)

BOARD = (
    "SITE-A NORTH GATE",
    "ATTENDANCE BOARD",
    "",
    "DAY  SAT 2026-08-01",
    "",
    "RAVI    IN  09:12",
    "RAVI    OUT 17:40",
    "",
    "PRIYA   IN  08:55",
    "PRIYA   OUT 13:05",
)

#: Which rows get a horizontal rule under them, so the board reads as a board
#: rather than as a wall of text.
RULED_AFTER = frozenset({1, 3})


def render(lines: tuple[str, ...]) -> bytes:
    """The board as PNG octets.  Deterministic: same input, same file."""
    columns = max(len(line) for line in lines)
    width = MARGIN * 2 + columns * (GLYPH_WIDTH + 1) * SCALE
    height = MARGIN * 2 + len(lines) * (GLYPH_HEIGHT * SCALE + LINE_GAP)
    canvas = [[PAPER] * width for _ in range(height)]

    for index, line in enumerate(lines):
        top = MARGIN + index * (GLYPH_HEIGHT * SCALE + LINE_GAP)
        _draw_line(canvas, line.upper(), top)
        if index in RULED_AFTER:
            _draw_rule(canvas, top + GLYPH_HEIGHT * SCALE + LINE_GAP // 2, width)
    return _png(canvas, width, height)


def _draw_line(canvas: list[list[tuple[int, int, int]]], text: str, top: int) -> None:
    for column, character in enumerate(text):
        glyph = GLYPHS.get(character, GLYPHS[" "])
        left = MARGIN + column * (GLYPH_WIDTH + 1) * SCALE
        for row, bits in enumerate(glyph):
            for bit, mark in enumerate(bits):
                if mark != "#":
                    continue
                _fill(canvas, left + bit * SCALE, top + row * SCALE, INK)


def _fill(
    canvas: list[list[tuple[int, int, int]]], left: int, top: int, colour: tuple[int, int, int]
) -> None:
    for row in range(SCALE):
        line = canvas[top + row]
        for column in range(SCALE):
            line[left + column] = colour


def _draw_rule(canvas: list[list[tuple[int, int, int]]], top: int, width: int) -> None:
    for column in range(MARGIN, width - MARGIN):
        canvas[top][column] = RULE


def _png(canvas: list[list[tuple[int, int, int]]], width: int, height: int) -> bytes:
    raw = bytearray()
    for row in canvas:
        raw.append(0)  # filter type 0: none
        for red, green, blue in row:
            raw.extend((red, green, blue))
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            _chunk(b"IHDR", header),
            _chunk(b"IDAT", zlib.compress(bytes(raw), 9)),
            _chunk(b"IEND", b""),
        )
    )


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return b"".join(
        (
            struct.pack(">I", len(payload)),
            kind,
            payload,
            struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF),
        )
    )


def main() -> None:
    target = Path(__file__).parent / "site-a" / "attendance-board-sat.png"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(render(BOARD))
    print(f"wrote {target} ({target.stat().st_size} octets)")


if __name__ == "__main__":
    main()
