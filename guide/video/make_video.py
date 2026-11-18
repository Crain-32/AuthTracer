"""Records a captioned tour of AuthTracer as an MP4: the CLI steps as terminal cards, then the UI, driven in Chrome.

It needs a running AuthTracer server holding the example system (guide/tutorial.md, parts 1 to 4) and Google Chrome:

    python3 -m venv build/video/.venv
    build/video/.venv/bin/pip install -r guide/video/requirements.txt
    build/video/.venv/bin/python guide/video/make_video.py --diff build/reports/authtracer/shortcut.json \
        --stills guide/images

It writes guide/video/authtracer-tour.mp4 (--out to change it), the tour that ships with the guide.

script.json holds what depends on the data: the terminal steps (paste real output there) and some captions.

Every frame is a screenshot of the real UI, so the video shows whatever the server holds. Captions and cards are
HTML, rendered by the same browser; Pillow moves the camera and blends the scenes; imageio-ffmpeg encodes H.264.
"""

import argparse
import html
import io
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import imageio_ffmpeg
from PIL import Image, ImageDraw
from playwright.sync_api import Locator, Page, sync_playwright

WIDTH, HEIGHT = 1920, 1080
FPS = 30
# The browser window. Screenshots are taken at twice this, so the camera can zoom in without blurring.
VIEW_W, VIEW_H = 1440, 810
SHOT_SCALE = 2
FADE = 0.45
ACCENT = (99, 102, 241)

Rect = tuple[float, float, float, float]  # x, y, width, height in screenshot pixels


@dataclass
class Scene:
    image: Image.Image
    seconds: float
    caption: Image.Image | None = None
    # Where the camera starts and ends, as crops of the image. None shows the whole image.
    start: Rect | None = None
    end: Rect | None = None
    highlights: list[Rect] = field(default_factory=list)


# ---------------------------------------------------------------------------------------------------------- cards

CARD_CSS = """
* { box-sizing: border-box; margin: 0; }
body { width: 1920px; height: 1080px; font-family: -apple-system, 'Inter', 'Segoe UI', sans-serif; color: #e7e9f3;
  background: radial-gradient(circle at 20% 15%, #2b2f6b 0%, #14162b 45%, #0b0c17 100%); display: flex;
  align-items: center; justify-content: center; }
.logo { width: 120px; height: 120px; border-radius: 28px; background: #6366f1; display: grid; place-items: center;
  box-shadow: 0 20px 60px rgba(99, 102, 241, .45); }
h1 { font-size: 104px; font-weight: 700; letter-spacing: -2px; }
.sub { font-size: 40px; color: #b8bdd8; margin-top: 18px; }
.small { font-size: 26px; color: #8a90b2; margin-top: 44px; }
.step { font-size: 26px; font-weight: 600; letter-spacing: 3px; text-transform: uppercase; color: #a5a8f8; }
.term { width: 1500px; border-radius: 18px; background: #0f111a; border: 1px solid #2a2e45;
  box-shadow: 0 30px 80px rgba(0, 0, 0, .5); overflow: hidden; margin-top: 30px; }
.bar { height: 52px; background: #1a1d2b; display: flex; align-items: center; gap: 12px; padding: 0 22px; }
.dot { width: 16px; height: 16px; border-radius: 50%; }
pre { font-family: 'JetBrains Mono', 'SF Mono', Menlo, monospace; font-size: 25px; line-height: 1.55;
  padding: 30px 36px 36px; white-space: pre-wrap; word-break: break-all; color: #d6d9e8; }
.cmd { color: #ffffff; } .prompt { color: #7cdba0; } .out { color: #9aa0bf; } .hi { color: #f5c46b; }
"""

SHIELD = ('<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" '
          'stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01'
          'C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 '
          '5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>')


def title_card(page: Page, title: str, subtitle: str, small: str) -> Image.Image:
    body = (f'<div style="text-align:center"><div style="display:flex;justify-content:center;margin-bottom:40px">'
            f'<div class="logo">{SHIELD}</div></div><h1>{html.escape(title)}</h1>'
            f'<div class="sub">{html.escape(subtitle)}</div><div class="small">{html.escape(small)}</div></div>')
    return render(page, body)


def terminal_card(page: Page, step: str, heading: str, command: str, output: list[str]) -> Image.Image:
    lines = [f'<span class="prompt">$</span> <span class="cmd">{html.escape(command)}</span>']
    for line in output:
        css = 'hi' if line.startswith('!') else 'out'
        lines.append(f'<span class="{css}">{html.escape(line.lstrip("!"))}</span>')
    dots = ''.join(f'<div class="dot" style="background:{color}"></div>' for color in ('#ff5f57', '#febc2e', '#28c840'))
    body = (f'<div><div class="step">{html.escape(step)}</div>'
            f'<div style="font-size:48px;font-weight:650;margin-top:10px;max-width:1500px">{html.escape(heading)}</div>'
            f'<div class="term"><div class="bar">{dots}</div><pre>{"<br>".join(lines)}</pre></div></div>')
    return render(page, body)


def render(page: Page, body: str) -> Image.Image:
    page.set_content(f'<html><head><style>{CARD_CSS}</style></head><body>{body}</body></html>')
    return Image.open(io.BytesIO(page.screenshot())).convert('RGB')


def caption(page: Page, chapter: str, text: str) -> Image.Image:
    """A lower third: the chapter in small capitals over one or two lines of explanation."""
    page.set_content(f"""<html><head><style>
      * {{ margin: 0; box-sizing: border-box; }}
      body {{ width: 1920px; background: transparent; font-family: -apple-system, 'Inter', sans-serif; }}
      .box {{ margin: 0 auto; width: fit-content; max-width: 1560px; padding: 22px 34px 24px; border-radius: 16px;
        background: rgba(13, 15, 28, .9); border-left: 6px solid rgb{ACCENT}; box-shadow: 0 12px 40px rgba(0,0,0,.35); }}
      .chapter {{ font-size: 20px; font-weight: 700; letter-spacing: 2.5px; text-transform: uppercase;
        color: #a5a8f8; }}
      .text {{ font-size: 31px; line-height: 1.38; color: #f2f3f9; margin-top: 6px; }}
    </style></head><body><div class="box"><div class="chapter">{html.escape(chapter)}</div>
      <div class="text">{html.escape(text)}</div></div></body></html>""")
    box = page.locator('.box').bounding_box()
    shot = page.screenshot(omit_background=True, clip={'x': 0, 'y': box['y'], 'width': 1920, 'height': box['height']})
    return Image.open(io.BytesIO(shot)).convert('RGBA')


# ------------------------------------------------------------------------------------------------------ the app

class App:
    def __init__(self, page: Page, url: str):
        self.page = page
        self.url = url.rstrip('/')

    def open(self, theme: str):
        self.page.add_init_script(f"localStorage.setItem('authtracer.theme', '{theme}')")
        self.page.goto(f'{self.url}/#paths')
        self.loaded('Latest stored system graph')

    def view(self, name: str):
        self.page.evaluate(f"location.hash = '#{name}'")
        self.settle()

    def settle(self, ms: int = 700):
        """Waits out a view's transitions (tooltips, the diagram's first layout); loads are waited for by loaded()."""
        self.page.wait_for_timeout(ms)

    def loaded(self, origin: str):
        """Waits until the stats bar names the graph that was asked for and nothing is loading."""
        self.page.locator('header .animate-spin').wait_for(state='detached')
        self.page.get_by_text(origin, exact=True).wait_for()
        self.settle(300)

    def shot(self) -> Image.Image:
        return Image.open(io.BytesIO(self.page.screenshot())).convert('RGB')

    def rect(self, selector: str, pad: float = 16) -> Rect:
        box = self.page.locator(selector).first.bounding_box()
        return (max(0, (box['x'] - pad) * SHOT_SCALE), max(0, (box['y'] - pad) * SHOT_SCALE),
                (box['width'] + 2 * pad) * SHOT_SCALE, (box['height'] + 2 * pad) * SHOT_SCALE)

    def scroll_main_to(self, target: Locator, offset: int = 24):
        target.evaluate(
            f'(el) => {{ const main = document.querySelector("main"); '
            f'main.scrollTop += el.getBoundingClientRect().top - main.getBoundingClientRect().top - {offset}; }}')
        self.settle(400)

    def choose(self, label: str, option: str):
        self.page.get_by_role('combobox', name=label).click()
        self.page.get_by_role('option', name=option, exact=True).click()
        self.settle()


# ------------------------------------------------------------------------------------------------------ camera

def fit(rect: Rect, image: Image.Image) -> Rect:
    """Grows a rect to the frame's aspect ratio and keeps it inside the image."""
    x, y, w, h = rect
    aspect = WIDTH / HEIGHT
    if w / h > aspect:
        h = w / aspect
    else:
        w = h * aspect
    w, h = min(w, image.width), min(h, image.height)
    cx, cy = rect[0] + rect[2] / 2, rect[1] + rect[3] / 2
    x = min(max(0, cx - w / 2), image.width - w)
    y = min(max(0, cy - h / 2), image.height - h)
    return x, y, w, h


def room(rect: Rect, scene: Scene) -> Rect:
    """Leaves space under what the camera looks at for the caption, so the caption doesn't cover it."""
    if scene.caption is None:
        return rect
    x, y, w, h = rect
    return x, y, w, h / (1 - (scene.caption.height + 60) / HEIGHT)


def ease(t: float) -> float:
    return t * t * (3 - 2 * t)


def frames(scene: Scene):
    full = (0, 0, scene.image.width, scene.image.height)
    start = fit(room(scene.start, scene) if scene.start else full, scene.image)
    end = fit(room(scene.end or scene.start, scene) if scene.end or scene.start else full, scene.image)
    count = max(1, round(scene.seconds * FPS))
    for index in range(count):
        # The camera moves during the middle of the scene and holds at both ends.
        t = ease(min(1, max(0, (index / max(1, count - 1) - 0.12) / 0.55)))
        crop = tuple(a + (b - a) * t for a, b in zip(start, end))
        frame = scene.image.resize((WIDTH, HEIGHT), Image.LANCZOS, box=(crop[0], crop[1], crop[0] + crop[2],
                                                                        crop[1] + crop[3]))
        appear = min(1, max(0, (index / FPS - 0.5) / 0.4))
        if scene.highlights and appear > 0:
            frame = highlight(frame, scene.highlights, crop, appear)
        if scene.caption is not None:
            frame = frame.convert('RGBA')
            layer = Image.new('RGBA', frame.size)
            layer.alpha_composite(fade(scene.caption, min(1, index / (FPS * 0.35))),
                                  (0, HEIGHT - scene.caption.height - 44))
            frame = Image.alpha_composite(frame, layer).convert('RGB')
        yield frame


def highlight(frame: Image.Image, rects: list[Rect], crop: Rect, alpha: float) -> Image.Image:
    layer = Image.new('RGBA', frame.size)
    draw = ImageDraw.Draw(layer)
    sx, sy = WIDTH / crop[2], HEIGHT / crop[3]
    for x, y, w, h in rects:
        box = ((x - crop[0]) * sx, (y - crop[1]) * sy, (x + w - crop[0]) * sx, (y + h - crop[1]) * sy)
        draw.rounded_rectangle(box, radius=14, outline=ACCENT + (round(255 * alpha),), width=5)
    return Image.alpha_composite(frame.convert('RGBA'), layer).convert('RGB')


def fade(image: Image.Image, alpha: float) -> Image.Image:
    if alpha >= 1:
        return image
    faded = image.copy()
    faded.putalpha(image.getchannel('A').point(lambda value: round(value * alpha)))
    return faded


def encode(scenes: list[Scene], out: Path):
    out.parent.mkdir(parents=True, exist_ok=True)
    writer = imageio_ffmpeg.write_frames(str(out), (WIDTH, HEIGHT), fps=FPS, codec='libx264', pix_fmt_out='yuv420p',
                                         macro_block_size=8, quality=None,
                                         output_params=['-crf', '18', '-preset', 'medium', '-movflags', '+faststart'])
    writer.send(None)
    previous = None
    total = 0
    try:
        for scene in scenes:
            for index, frame in enumerate(frames(scene)):
                if previous is not None and index < FADE * FPS:
                    frame = Image.blend(previous, frame, ease(index / (FADE * FPS)))
                writer.send(frame.tobytes())
                total += 1
            # The next scene fades in from this one's last frame.
            previous = frame
    finally:
        writer.close()
    print(f'Wrote {out} ({total / FPS:.0f} s, {total} frames)')


# ------------------------------------------------------------------------------------------------------ the tour

def tour(app: App, cards: Page, diff: Path | None, script: dict, stills: dict[str, Image.Image]) -> list[Scene]:
    """The scenes, in the tutorial's order. Shots that the tutorial shows are kept in stills by name."""
    scenes: list[Scene] = []
    page = app.page
    terminal = {step['id']: step for step in script['terminal']}

    def add(image, seconds, chapter=None, text=None, still=None, **camera):
        if still:
            stills[still] = image
        scenes.append(Scene(image, seconds, caption(cards, chapter, text) if text else None, **camera))

    def term(step_id):
        step = terminal[step_id]
        add(terminal_card(cards, step['step'], step['heading'], step['command'], step['output']), step['seconds'])

    def expand(route):
        """Opens the card listing the route (exactly, not a longer route containing it)."""
        code = page.locator('code').filter(has_text=re.compile(f'^{re.escape(route)}$'))
        trigger = page.locator('main button[aria-expanded]').filter(has=code).first
        if not trigger.count():
            raise SystemExit(f'No card lists {route} on its own line (folded into "N endpoints"?): '
                             'pick another route in script.json')
        if trigger.get_attribute('aria-expanded') == 'false':
            trigger.click()
        app.settle(900)
        app.scroll_main_to(trigger)

    add(title_card(cards, 'AuthTracer', 'Who can reach what, across your Spring services',
                   'A tour: scan, link, read the graph, and check a pull request'), 4.5)

    # One service
    term('scan')
    app.choose('Stored service graph', script['first_service']['service'])
    app.loaded(f"Stored graph of {script['first_service']['service']}")
    expand(script['first_service']['route'])
    add(app.shot(), 7, 'One service', script['first_service']['caption'], still='paths')

    # The system
    term('link')
    page.get_by_role('button', name='Latest system graph').click()
    app.loaded('Latest stored system graph')
    app.view('paths')
    add(app.shot(), 5.5, 'Request paths', 'Every endpoint of every service, with what it requires. Endpoints whose '
        'paths end the same way share a card, so the differences stand out.')
    expand('/profiles/{id}')
    add(app.shot(), 8, 'Across services', 'One lane per service, steps in the order they run. Violet arrows are calls '
        'to other services, with counts from the traces; every check shows how often it granted and denied.',
        still='paths-card', end=app.rect('main .react-flow', pad=4))
    page.locator('main .react-flow__node:has-text("ROLE_ADMIN")').first.click()
    app.settle()
    add(app.shot(), 6.5, 'Details', 'Click any step for its details: what it requires, how it was written, where it '
        'is in the code, and what happens when it denies.', highlights=[app.rect('aside', pad=0)])

    # Field lineage and exposures
    app.view('lineage')
    app.choose('Endpoint', script['lineage']['endpoint'])
    app.choose('Field', script['lineage']['field'])
    add(app.shot(), 8.5, 'Field lineage', script['lineage']['caption'], still='lineage',
        end=app.rect('main .react-flow', pad=4))
    app.view('exposures')
    page.get_by_label('Filter exposures').fill(script['exposures']['filter'])
    app.settle()
    add(app.shot(), 7, 'Exposures', script['exposures']['caption'], still='exposures')

    # Findings and identities
    app.view('findings')
    add(app.shot(), 6, 'Findings', 'What the scan wants a person to look at: checks that are skipped on some path, '
        'configuration it cannot read, sensitive endpoints anyone can reach.', still='findings')
    app.view('identities')
    add(app.shot(), 6.5, 'Identities', 'From the traces: what each test identity was granted, and which of it the '
        'checks on its requests actually needed. The rest is over-scoped.', still='identities')

    # The pull-request check
    if diff:
        term('diff')
        page.locator('input[type=file]').set_input_files(str(diff))
        page.locator('main h2:has-text("Diff report")').wait_for()
        app.settle(900)
        add(app.shot(), 8, 'Diff report', script['diff_caption'], still='diff')

    # Legend and the dark theme
    app.view('legend')
    add(app.shot(), 5, 'Legend', 'Every shape, color and line in the diagrams, drawn the way the views draw them.')
    page.get_by_label('Toggle theme').click()
    app.view('paths')
    expand('/profiles/{id}')
    add(app.shot(), 5, 'Light or dark', 'Both themes, from the switch at the bottom of the sidebar.')

    add(title_card(cards, 'Try it', 'guide/tutorial.md walks through every step',
                   'Scan · Link · Read · Check every pull request'), 4.5)
    return scenes


def save_stills(stills: dict[str, Image.Image], directory: Path):
    """The tutorial's screenshots, at 1600 pixels wide: sharp on most screens, small enough for a repository."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, image in stills.items():
        still = image.resize((1600, round(image.height * 1600 / image.width)), Image.LANCZOS)
        still.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(
            directory / f'{name}.png', optimize=True)
        print(f'Wrote {directory / name}.png')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--url', default='http://localhost:8080', help='the AuthTracer server')
    parser.add_argument('--diff', type=Path, help='a diff report (diff --json) to show in the Diff report view')
    parser.add_argument('--script', type=Path, default=Path(__file__).with_name('script.json'),
                        help='the terminal steps and captions that depend on the data')
    parser.add_argument('--out', type=Path, default=Path(__file__).with_name('authtracer-tour.mp4'))
    parser.add_argument('--headed', action='store_true', help='show the browser while recording')
    parser.add_argument('--stills', type=Path, help='also save the tutorial\'s screenshots to this directory')
    args = parser.parse_args()
    script = json.loads(args.script.read_text())

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=not args.headed)
        page = browser.new_page(viewport={'width': VIEW_W, 'height': VIEW_H}, device_scale_factor=SHOT_SCALE)
        cards = browser.new_page(viewport={'width': WIDTH, 'height': HEIGHT})
        app = App(page, args.url)
        app.open('light')
        stills: dict[str, Image.Image] = {}
        scenes = tour(app, cards, args.diff, script, stills)
        browser.close()
    if args.stills:
        save_stills(stills, args.stills)
    encode(scenes, args.out)


if __name__ == '__main__':
    main()
