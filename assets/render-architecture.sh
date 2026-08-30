#!/usr/bin/env bash
#
#  Render assets/muster-architecture.svg to assets/muster-architecture.png.
#
#  The PNG in this repository is a *derived* file, and the only honest way to
#  keep it that way is for regenerating it to be one command rather than a
#  remembered sequence of clicks in an image editor.  Otherwise the SVG and the
#  PNG drift, and the README ends up showing an architecture the SVG no longer
#  describes -- which is exactly what happened to the previous diagram.
#
#  Headless Chrome is the renderer because it is the same engine that renders
#  the SVG for anyone who opens it, so the two cannot disagree about a font
#  fallback or a text anchor.  The size is pinned to the SVG's own viewBox and
#  the scale factor is pinned here, so the same input produces the same output
#  bytes-for-purpose on any machine with the same Chrome.
#
#  Usage:
#
#      assets/render-architecture.sh                 # find Chrome automatically
#      CHROME=/path/to/chrome assets/render-architecture.sh
#
set -euo pipefail

#  The SVG's viewBox. Change these together with the viewBox and nowhere else.
readonly WIDTH=1200
readonly HEIGHT=1650

#  Two device pixels per SVG pixel: readable when a judge zooms into the
#  receipt row, still small enough to commit.
readonly SCALE=2

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SOURCE="${here}/muster-architecture.svg"
readonly TARGET="${here}/muster-architecture.png"

find_chrome() {
  if [[ -n "${CHROME:-}" ]]; then
    printf '%s' "${CHROME}"
    return
  fi
  local candidate
  for candidate in \
    "/c/Program Files/Google/Chrome/Application/chrome.exe" \
    "/c/Program Files (x86)/Google/Chrome/Application/chrome.exe" \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "$(command -v google-chrome || true)" \
    "$(command -v google-chrome-stable || true)" \
    "$(command -v chromium || true)" \
    "$(command -v chromium-browser || true)"; do
    if [[ -n "${candidate}" && -x "${candidate}" ]]; then
      printf '%s' "${candidate}"
      return
    fi
  done
  echo "no Chrome or Chromium found; set CHROME=/path/to/chrome" >&2
  exit 1
}

main() {
  local chrome
  chrome="$(find_chrome)"

  #  Chrome writes the screenshot relative to its working directory on some
  #  platforms, so it is given an absolute destination and an absolute source.
  local source_url
  case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) source_url="file:///$(cygpath -m "${SOURCE}")" ;;
    *) source_url="file://${SOURCE}" ;;
  esac

  local destination="${TARGET}"
  if command -v cygpath >/dev/null 2>&1; then
    destination="$(cygpath -m "${TARGET}")"
  fi

  "${chrome}" \
    --headless \
    --disable-gpu \
    --hide-scrollbars \
    --force-device-scale-factor="${SCALE}" \
    --default-background-color=FFFFFFFF \
    --window-size="${WIDTH},${HEIGHT}" \
    --screenshot="${destination}" \
    "${source_url}" >/dev/null 2>&1

  if [[ ! -s "${TARGET}" ]]; then
    echo "Chrome produced no image at ${TARGET}" >&2
    exit 1
  fi
  echo "wrote ${TARGET} at $((WIDTH * SCALE))x$((HEIGHT * SCALE))"
}

main "$@"
