"""Render the README demo animations from stage.html.

    pip install playwright pillow numpy
    python docs/demo/render.py                  # all scenes, both languages, 60 fps animated WebP
    python docs/demo/render.py approve --lang en
    python docs/demo/render.py --format gif     # GIF instead (256 colors, at most 50 fps)

Uses the installed Microsoft Edge (no Playwright browser download needed).
"""

import argparse
import io
import sys
from pathlib import Path

import numpy as np
from PIL import Image
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "images"
SCENES = ["approve", "unlock", "keys", "audit"]
LANGS = ["zh", "en"]
HOLD_MS = 1200  # linger on the last frame before looping


def capture(page, scene: str, lang: str, fps: int) -> list[Image.Image]:
    page.goto(f"{(HERE / 'stage.html').as_uri()}?scene={scene}&lang={lang}&render=1")
    page.evaluate("window.READY")
    duration = page.evaluate("window.DURATION")
    frames = []
    for i in range(round(duration * fps)):
        page.evaluate(f"window.seek({i / fps})")
        png = page.screenshot(clip={"x": 0, "y": 0, "width": 960, "height": 600})
        frames.append(Image.open(io.BytesIO(png)).convert("RGB"))
    return frames


def frame_durations(count: int, fps: int, unit: int) -> list[int]:
    """Per-frame delays in ms, rounded to the format's time unit without drifting (60 fps → 17, 17, 16, …)."""
    edges = [round(i * 1000 / fps / unit) * unit for i in range(count + 1)]
    durations = [b - a for a, b in zip(edges, edges[1:])]
    durations[-1] = HOLD_MS
    return durations


def encode_webp(frames: list[Image.Image], path: Path, fps: int) -> None:
    # Lossy q90 is visually identical here (mean error < 1/255) at a fraction of the lossless size;
    # the encoder stores only the changed region of each frame.
    frames[0].save(path, save_all=True, append_images=frames[1:], duration=frame_durations(len(frames), fps, 1),
                   loop=0, quality=90, method=4)


def encode_gif(frames: list[Image.Image], path: Path, fps: int) -> None:
    # One palette for the whole clip keeps static areas byte-identical between frames,
    # so the GIF encoder only stores the regions that actually change.
    samples = frames[:: max(1, len(frames) // 24)]
    sheet = Image.new("RGB", (samples[0].width, samples[0].height * len(samples)))
    for i, f in enumerate(samples):
        sheet.paste(f, (0, i * f.height))
    palette = sheet.quantize(colors=255, method=Image.Quantize.MEDIANCUT)
    indexed = [np.asarray(f.quantize(palette=palette, dither=Image.Dither.NONE)) for f in frames]
    # Pixels that did not change since the previous frame become transparent (index 255), which
    # LZW compresses into long runs; the encoder then crops each frame to the changed area.
    out = [indexed[0]]
    for prev, cur in zip(indexed, indexed[1:]):
        out.append(np.where(cur == prev, 255, cur).astype(np.uint8))
    pal = palette.getpalette()[: 255 * 3] + [255, 0, 255]
    images = []
    for a in out:
        im = Image.fromarray(a, "P")
        im.putpalette(pal)
        images.append(im)
    images[0].save(path, save_all=True, append_images=images[1:], duration=frame_durations(len(images), fps, 10),
                   loop=0, optimize=False, disposal=1, transparency=255)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("scenes", nargs="*", choices=SCENES)
    ap.add_argument("--lang", choices=LANGS, action="append")
    ap.add_argument("--format", choices=["webp", "gif"], default="webp")
    ap.add_argument("--fps", type=int, help="default: 60 for WebP, 50 for GIF")
    args = ap.parse_args()
    fps = args.fps or (60 if args.format == "webp" else 50)
    if args.format == "gif" and fps > 50:
        ap.error("browsers slow down GIF frames shorter than 20 ms; use --fps 50 or lower")
    encode = encode_webp if args.format == "webp" else encode_gif
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge")
        page = browser.new_page(viewport={"width": 960, "height": 600}, device_scale_factor=1)
        page.on("pageerror", lambda e: sys.exit(f"page error: {e}"))
        for lang in args.lang or LANGS:
            for scene in args.scenes or SCENES:
                frames = capture(page, scene, lang, fps)
                path = OUT / f"demo-{scene}.{lang}.{args.format}"
                encode(frames, path, fps)
                print(f"{path.relative_to(HERE.parent.parent)}  {len(frames)} frames  {path.stat().st_size / 1e6:.2f} MB")
        browser.close()


if __name__ == "__main__":
    main()
