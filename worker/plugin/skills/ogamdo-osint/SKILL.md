---
name: ogamdo-osint
description: Locating a place from a photograph - which reverse-image engines and mapping services are reachable from this platform, which are gated, and the keyless satellite/terrain/feature APIs that answer without fighting anyone's bot detection. Read this before a geolocation challenge.
---

# Finding where a photo was taken

Job ba2725c84be2 spent 145 turns and $26 on one strategy — reverse image
search — and returned no flag. It never queried terrain, features or
coordinates once. This is the wider set, and what each one costs you.

## Google Earth does NOT work here

`earth.google.com/web/` loads its splash screen and then stops:
`Error: WebGL is not supported on your browser`. The chromium in this image
ships `libvk_swiftshader.so` but software WebGL does not come up, with or
without `--use-gl=angle --use-angle=swiftshader --enable-unsafe-swiftshader`.
Verified by screenshot, not assumed. Do not spend turns on it.

The capability you actually want — look at the ground from above — is below,
and it is keyless.

## Satellite and terrain, keyless and scriptable

Slippy-map tiles, `{z}/{x}/{y}`, 256px. All verified 200 from this container.

    # satellite
    https://services.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}
    # terrain + contours - the one that matches a mountain skyline
    https://tile.opentopomap.org/{z}/{x}/{y}.png
    # streets and labels
    https://tile.openstreetmap.org/{z}/{x}/{y}.png

Note ArcGIS puts **{y} before {x}**; the other two are {x} then {y}.

    import math
    def tile(lat, lon, z):
        n = 2 ** z
        x = int((lon + 180.0) / 360.0 * n)
        y = int((1 - math.asinh(math.tan(math.radians(lat))) / math.pi) / 2 * n)
        return x, y

Stitch a few tiles with PIL and `Read` the result — you can look at images
now. Set a real User-Agent; tile servers refuse a blank one.

`mt1.google.com/vt` answers too. It is an undocumented internal endpoint and
not part of this list; ArcGIS and OpenTopoMap cover the same need openly.

## Asking questions instead of looking

    # features near a point, or anywhere: "waterfall with a trail", "peak above 2000m"
    https://overpass-api.de/api/interpreter        POST an Overpass QL query
    # name -> coordinates, and the reverse
    https://nominatim.openstreetmap.org/search?q=<name>&format=json
    # what is documented within N metres of a point
    https://en.wikipedia.org/w/api.php?action=query&list=geosearch&gscoord=<lat>|<lon>&gsradius=10000&format=json
    # other photographs of the same place
    https://commons.wikimedia.org/w/api.php?action=query&list=search&srsearch=<terms>&format=json

All four returned 200 from this container, need no key, and permit automated
access. A vegetation read ("Scots pine and birch, so boreal") plus one
Overpass query over candidate regions narrows harder than another engine that
has already said zero.

## Reverse image search - what works and what does not

Bing, `html.duckduckgo.com` and Yandex answer to a scripted client (200).
TinEye's scrape path returns 403; its API needs a key.

**Google Lens is gated.** The upload succeeds and Google issues a `vsrid`,
then the result page redirects to `/sorry/index` with a reCAPTCHA. A genuine
mouse press on the checkbox did not pass it — it is client-reputation, not a
token you can solve. Proxy IPs are worse, being datacenter ranges.

That gate belongs to Google, which is not your challenge. Do not spend the
job on it. Report the wall, say plainly that an unblocked browser would
settle it in under a minute, and spend your turns on the routes above.

### WHAT IS BLOCKED IS THE BROWSER, NOT THIS NETWORK

Measured on the same egress IP, at the same time:

    curl "https://www.google.com/search?q=weather"     -> 200, a real results page
    worker.browser render (CDP-driven chromium)        -> /sorry

Google's JS fingerprinting catches the automated browser. The IP is fine.

So when a page does NOT need JavaScript — a text search, an API, a static
document — **drop to curl** instead of escalating the browser. Job
117c98fac9b8 hit /sorry on a plain text query for the one string it had read
off the photo, concluded Google was closed, and went back to engines that had
already returned nothing. The same query over curl would have answered.

`--stealth` is the wrong instinct here and is now refused in code against
anything that is not this job's declared target or a private address. It also
made things measurably worse: it walks further INTO the fingerprint check
that is doing the blocking.

## Order that costs least

1. Read the file out: EXIF, GPS, embedded thumbnails, trailing bytes.
2. Read the photo: text on signage and clothing, vehicle plates, vegetation,
   architecture, sun angle, snow line.
3. Text-search any string you read. It is cheap and un-gated.
4. Reverse image on Bing / DuckDuckGo / Yandex — once each, not repeatedly.
5. Turn the visual facts into a QUERY: Overpass, Nominatim, geosearch.
6. Confirm a candidate against ArcGIS imagery and OpenTopoMap contours.

Never convert a guess into a flag. A place name you reasoned toward but did
not confirm against a source is a guess, and a wrong flag scores zero.
