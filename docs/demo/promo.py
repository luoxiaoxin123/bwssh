"""Render the bwssh promo video (1920×1080, 60 fps, H.264 + AAC) from promo.html.

    pip install playwright pillow numpy imageio-ffmpeg
    python docs/demo/promo.py                          # writes artifacts/bwssh-promo.mp4
    python docs/demo/promo.py --stills 3,12.5,45       # PNG previews of single frames instead

The soundtrack is synthesized here: a pad/arp/kick bed plus sound effects at the times promo.html
lists in window.AUDIO. Uses the installed Microsoft Edge (no Playwright browser download needed).
"""

import argparse
import functools
import http.server
import subprocess
import sys
import tempfile
import threading
import wave
from pathlib import Path

import imageio_ffmpeg
import numpy as np
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SR = 48000


# ---------------------------------------------------------------- serving

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def serve() -> http.server.ThreadingHTTPServer:
    handler = functools.partial(QuietHandler, directory=str(ROOT))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# ---------------------------------------------------------------- audio

rng = np.random.default_rng(7)


def hz(midi: float) -> float:
    return 440.0 * 2 ** ((midi - 69) / 12)


def tt(seconds: float) -> np.ndarray:
    return np.arange(int(seconds * SR)) / SR


def adsr(n: int, a: float, r: float) -> np.ndarray:
    t = np.arange(n) / SR
    return np.minimum(1, t / max(a, 1e-4)) * np.clip((n / SR - t) / max(r, 1e-4), 0, 1)


def lowpass(x: np.ndarray, cutoff) -> np.ndarray:
    """One-pole lowpass; cutoff may be a per-sample array."""
    c = np.broadcast_to(np.asarray(cutoff, dtype=float), x.shape)
    k = 1 - np.exp(-2 * np.pi * c / SR)
    y = np.empty_like(x)
    acc = 0.0
    for i in range(len(x)):
        acc += k[i] * (x[i] - acc)
        y[i] = acc
    return y


class Mix:
    def __init__(self, seconds: float):
        self.n = int(seconds * SR) + SR * 3
        self.dry = np.zeros((self.n, 2))
        self.send = np.zeros((self.n, 2))

    def add(self, t: float, mono: np.ndarray, gain=1.0, pan=0.0, reverb=0.0):
        i = int(t * SR)
        if i >= self.n or i + len(mono) <= 0:
            return
        mono = mono[: self.n - i]
        l, r = np.cos((pan + 1) * np.pi / 4), np.sin((pan + 1) * np.pi / 4)
        seg = np.stack([mono * l, mono * r], axis=1) * gain * np.sqrt(2)
        self.dry[i : i + len(mono)] += seg
        if reverb:
            self.send[i : i + len(mono)] += seg * reverb

    def render(self) -> np.ndarray:
        ir_t = tt(2.4)
        ir = np.stack([rng.standard_normal(len(ir_t)) * np.exp(-ir_t * 3.0) for _ in range(2)], axis=1)
        ir[: int(0.012 * SR)] = 0  # pre-delay
        size = 1 << int(np.ceil(np.log2(self.n + len(ir_t))))
        wet = np.stack([np.fft.irfft(np.fft.rfft(self.send[:, c], size) * np.fft.rfft(ir[:, c], size), size)[: self.n] for c in range(2)], axis=1)
        wet /= max(1e-9, np.abs(wet).max()) / max(1e-9, np.abs(self.send).max() * 0.9)
        return self.dry + wet * 0.55


def tone(freq, seconds, harmonics=(1.0,), decay=None, attack=0.004):
    t = tt(seconds)
    f = np.broadcast_to(np.asarray(freq, dtype=float), t.shape) if np.ndim(freq) else np.full(t.shape, float(freq))
    phase = 2 * np.pi * np.cumsum(f) / SR
    x = sum(a * np.sin(phase * (h + 1)) for h, a in enumerate(harmonics))
    env = np.minimum(1, t / attack)
    if decay:
        env *= np.exp(-t / decay)
    return x * env


def noise(seconds):
    return rng.standard_normal(int(seconds * SR))


def sfx(kind: str) -> tuple[np.ndarray, float, float]:
    """Returns (mono, gain, reverb send)."""
    if kind == "whoosh":
        n = noise(0.9)
        t = tt(0.9)
        cut = 200 + 2600 * np.sin(np.pi * np.clip(t / 0.9, 0, 1)) ** 2
        return lowpass(n, cut) * np.sin(np.pi * t / 0.9) ** 2, 0.12, 0.3
    if kind == "boom":
        f = 38 + 60 * np.exp(-tt(1.6) / 0.08)
        return tone(f, 1.6, (1.0, 0.25), decay=0.55) + lowpass(noise(1.6), 300) * np.exp(-tt(1.6) / 0.25) * 0.8, 0.75, 0.25
    if kind == "shimmer":
        out = np.zeros(int(1.8 * SR))
        for j, m in enumerate([86, 90, 93, 98, 102]):
            s = tone(hz(m), 1.8 - j * 0.06, (1.0, 0.2), decay=0.6)
            out[int(j * 0.06 * SR) : int(j * 0.06 * SR) + len(s)] += s
        return out, 0.08, 0.9
    if kind == "pop":
        f = 520 + 380 * (1 - np.exp(-tt(0.12) / 0.03))
        return tone(f, 0.12, (1.0, 0.3), decay=0.035), 0.16, 0.3
    if kind == "blip":
        return tone(1320, 0.1, (1.0, 0.25), decay=0.03), 0.11, 0.35
    if kind == "tick":
        return tone(2100, 0.04, (1.0,), decay=0.008), 0.08, 0.2
    if kind == "type":
        n = np.diff(noise(0.025), prepend=0) * np.exp(-tt(0.025) / 0.004)
        return n + tone(1800 + rng.uniform(-300, 300), 0.025, decay=0.004) * 0.5, 0.05, 0.05
    if kind in ("click", "enter"):
        n = np.diff(noise(0.06), prepend=0) * np.exp(-tt(0.06) / 0.003)
        body = tone(900 if kind == "click" else 400, 0.06, decay=0.012)
        return n * 0.6 + body, 0.2 if kind == "click" else 0.22, 0.1
    if kind == "chime":
        out = np.zeros(int(1.4 * SR))
        for j, m in enumerate([81, 86]):
            s = tone(hz(m), 1.2, (1.0, 0.35, 0.1), decay=0.4)
            out[int(j * 0.13 * SR) : int(j * 0.13 * SR) + len(s)] += s
        return out, 0.16, 0.5
    if kind == "success":
        out = np.zeros(int(1.0 * SR))
        for j, m in enumerate([74, 78, 81, 86]):
            s = tone(hz(m), 0.8, (1.0, 0.3), decay=0.22)
            out[int(j * 0.06 * SR) : int(j * 0.06 * SR) + len(s)] += s
        return out, 0.12, 0.45
    if kind == "error":
        out = np.zeros(int(0.5 * SR))
        for j, (a, b) in enumerate([(52, 53), (47, 48)]):
            s = tone(hz(a), 0.22, (1.0, 0.5, 0.33, 0.25), decay=0.12) + tone(hz(b), 0.22, (1.0, 0.5, 0.33, 0.25), decay=0.12)
            out[int(j * 0.17 * SR) : int(j * 0.17 * SR) + len(s)] += s
        return out, 0.12, 0.2
    if kind == "scan":
        f = 380 * 2 ** (2 * tt(1.2) / 1.2)
        return tone(f, 1.2, (1.0, 0.2)) * np.sin(np.pi * tt(1.2) / 1.2) * (0.6 + 0.4 * np.sin(2 * np.pi * 14 * tt(1.2))), 0.05, 0.4
    raise ValueError(kind)


def soundtrack(events: list[dict], duration: float) -> np.ndarray:
    mix = Mix(duration)
    beat = 60 / 100
    groove = (9.6, 77.8)  # kick, bass and arp run while the argument is being made
    chords = [[50, 57, 61, 64, 66], [47, 54, 57, 62, 66], [43, 50, 54, 59, 62], [45, 52, 57, 61, 64]]
    bar2 = beat * 8

    # pad (ducked under the kick while the groove runs)
    duck = np.ones(mix.n)
    kicks = [k * beat for k in range(int(groove[0] / beat), int(groove[1] / beat))]
    for k in kicks:
        i = int(k * SR)
        seg = duck[i : i + int(0.4 * SR)]
        seg *= 1 - 0.55 * np.exp(-np.arange(len(seg)) / SR / 0.11)
    for c in range(int(duration / bar2) + 1):
        start = c * bar2
        notes = chords[c % 4]
        for m in notes:
            for det, pan in ((-0.07, -0.6), (0.0, 0.0), (0.07, 0.6)):
                x = tone(hz(m + det), bar2 + 1.6, (1.0, 0.45, 0.22, 0.1, 0.05), attack=0.9)
                x *= adsr(len(x), 0.9, 1.6)
                level = 0.022 if start >= 5.4 else 0.014
                mix.add(start, x, gain=level, pan=pan, reverb=0.35)
        # bass
        if groove[0] <= start < groove[1]:
            x = tone(hz(notes[0] - 12), bar2, (1.0, 0.3), attack=0.02) * adsr(int(bar2 * SR), 0.02, 0.2)
            mix.add(start, x, gain=0.14)
        # arp
        if groove[0] - 0.01 <= start < groove[1]:
            order = [0, 2, 4, 3, 1, 3, 4, 2, 0, 2, 4, 3, 1, 3, 4, 2]
            for j, o in enumerate(order):
                x = tone(hz(notes[o] + 12), 0.5, (1.0, 0.25), decay=0.16)
                mix.add(start + j * beat / 2, x, gain=0.045, pan=0.35 if j % 2 else -0.35, reverb=0.5)
    bed = mix.dry.copy()  # pad, bass and arp: ducked under the kick at the end
    mix.dry[:] = 0

    # drums
    kick = tone(45 + 90 * np.exp(-tt(0.45) / 0.03), 0.45, (1.0,), decay=0.13)
    for k in kicks:
        mix.add(k, kick, gain=0.5)
    hat = np.diff(noise(0.05), prepend=0) * np.exp(-tt(0.05) / 0.012)
    for k in kicks:
        if k >= 21.0:
            mix.add(k + beat / 2, hat, gain=0.05, pan=0.2)

    # the ending chord rings out
    for m in [38, 50, 57, 61, 66, 69]:
        x = tone(hz(m), 5.5, (1.0, 0.4, 0.15), attack=0.05) * adsr(int(5.5 * SR), 0.05, 4.5)
        mix.add(77.8, x, gain=0.03, reverb=0.5)

    for e in events:
        x, gain, rv = sfx(e["k"])
        pan = float(np.clip((e["t"] * 7.3) % 2 - 1, -0.4, 0.4)) if e["k"] in ("type", "pop", "blip") else 0.0
        mix.add(e["t"], x, gain=gain, pan=pan, reverb=rv)

    out = mix.render() + bed * duck[:, None]
    out = out[: int((duration + 0.2) * SR)]
    t = np.arange(len(out)) / SR
    out *= np.clip(t / 0.4, 0, 1)[:, None] * np.clip((duration + 0.2 - t) / 1.6, 0, 1)[:, None]
    out = np.tanh(out * 1.2) / np.tanh(1.2)
    return out / np.abs(out).max() * 0.89


def write_wav(path: Path, audio: np.ndarray) -> None:
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes((audio * 32767).astype("<i2").tobytes())


# ---------------------------------------------------------------- video

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts" / "bwssh-promo.mp4")
    ap.add_argument("--fps", type=int, default=60)
    ap.add_argument("--crf", type=int, default=16)
    ap.add_argument("--stills", help="comma-separated times; writes PNGs next to --out instead of a video")
    ap.add_argument("--audio-only", action="store_true", help="write just the soundtrack as a WAV next to --out")
    args = ap.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    server = serve()
    url = f"http://127.0.0.1:{server.server_address[1]}/docs/demo/promo.html?render=1"
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge")
        page = browser.new_page(viewport={"width": 1920, "height": 1080})
        page.on("pageerror", lambda e: sys.exit(f"page error: {e}"))
        page.goto(url)
        page.evaluate("window.READY")
        duration = page.evaluate("window.DURATION")
        if args.stills:
            for s in args.stills.split(","):
                page.evaluate(f"window.seek({float(s)})")
                path = args.out.parent / f"promo-{float(s):06.2f}.png"
                page.screenshot(path=str(path))
                print(path)
            return
        events = page.evaluate("window.AUDIO")
        if args.audio_only:
            path = args.out.with_suffix(".wav")
            write_wav(path, soundtrack(events, duration))
            print(path)
            return
        with tempfile.TemporaryDirectory() as tmp:
            wav = Path(tmp) / "soundtrack.wav"
            write_wav(wav, soundtrack(events, duration))
            print(f"soundtrack: {len(events)} sound effects")
            cmd = [
                imageio_ffmpeg.get_ffmpeg_exe(), "-y", "-loglevel", "error",
                "-f", "image2pipe", "-c:v", "png", "-framerate", str(args.fps), "-i", "-",
                "-i", str(wav), "-map", "0:v", "-map", "1:a",
                "-vf", "scale=out_color_matrix=bt709:out_range=tv,format=yuv420p",
                "-c:v", "libx264", "-preset", "slow", "-crf", str(args.crf), "-tune", "animation",
                "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709",
                "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart", "-shortest", str(args.out),
            ]
            ff = subprocess.Popen(cmd, stdin=subprocess.PIPE)
            total = round(duration * args.fps)
            for i in range(total):
                page.evaluate(f"window.seek({i / args.fps})")
                ff.stdin.write(page.screenshot(type="png"))
                if i % (args.fps * 5) == 0:
                    print(f"  {i / args.fps:5.1f}s / {duration:.0f}s", flush=True)
            ff.stdin.close()
            if ff.wait():
                sys.exit("ffmpeg failed")
        browser.close()
    server.shutdown()
    print(f"{args.out}  {args.out.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
