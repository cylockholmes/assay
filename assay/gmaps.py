"""Google API key verification.

Ported from gmapsapiscanner (github.com/ozguralp/gmapsapiscanner): one request
per Google API, and a key is "accepted" by an API when Google answers without
an auth error. A browser Maps key is meant to be locked to the owner's
referrers and to the APIs the app uses; one that is accepted from a bare client
by billable APIs lets anyone run up the owner's Google Cloud bill.

The requests go to Google, never to the target. Each one is a single cheap
call billed to the key's owner.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from assay.net import Resp

_JSON = {"Content-Type": "application/json"}


def _ok_no_marker(*markers: str) -> Callable[[Resp], bool]:
    """HTTP 200 and none of the error markers anywhere in the body."""
    return lambda r: r.status == 200 and not any(m in r.body for m in markers)


def _image(r: Resp) -> bool:
    return r.status == 200 and r.content_type.startswith("image/")


def _redirect(r: Resp) -> bool:
    return r.status == 302


def _json_200(r: Resp) -> bool:
    # gmapsapiscanner accepts any 200 here; a catch-all HTML 200 would then
    # read as a push-takeover or data-exposure finding, so require JSON.
    return r.status == 200 and "json" in r.content_type


@dataclass
class Probe:
    name: str
    method: str
    url: str                              # contains {key}
    judge: Callable[[Resp], bool]
    cost: str
    body: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    key_header: bool = False              # key goes in Authorization, not the URL
    severity_bump: bool = False           # data exposure / takeover, not just billing


_M = "https://maps.googleapis.com/maps/api"
_ROADS = "https://roads.googleapis.com/v1"
_ROUTES_MATRIX_BODY = json.dumps({
    "origins": [{"waypoint": {"location": {"latLng": {
        "latitude": 37.419734, "longitude": -122.0827784}}}}],
    "destinations": [
        {"waypoint": {"location": {"latLng": {"latitude": 37.4220, "longitude": -122.0841}}}},
        {"waypoint": {"location": {"latLng": {"latitude": 37.4250, "longitude": -122.0860}}}},
    ],
    "travelMode": "DRIVE"})
_ROUTES_BODY = json.dumps({
    "origin": {"location": {"latLng": {"latitude": 37.419734, "longitude": -122.0827784}}},
    "destination": {"location": {"latLng": {"latitude": 37.4220, "longitude": -122.0841}}},
    "travelMode": "DRIVE"})

PROBES: List[Probe] = [
    Probe("Static Maps", "GET",
          _M + "/staticmap?center=45%2C10&zoom=7&size=400x400&key={key}",
          _image, "$2 per 1000 requests"),
    Probe("Street View Static", "GET",
          _M + "/streetview?size=400x400&location=40.720032,-73.988354"
               "&fov=90&heading=235&pitch=10&key={key}",
          _image, "$7 per 1000 requests"),
    Probe("Directions", "GET",
          _M + "/directions/json?origin=Disneyland"
               "&destination=Universal+Studios+Hollywood4&key={key}",
          _ok_no_marker("error_message"), "$5-10 per 1000 requests"),
    Probe("Geocoding", "GET", _M + "/geocode/json?latlng=40,30&key={key}",
          _ok_no_marker("error_message"), "$5 per 1000 requests"),
    Probe("Distance Matrix", "GET",
          _M + "/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998"
               "&destinations=" + "%7C".join(
                   ["40.6905615%2C-73.9976592"] * 6
                   + ["40.659569%2C-73.933783", "40.729029%2C-73.851524",
                      "40.6860072%2C-73.6334271", "40.598566%2C-73.7527626"] * 2)
          + "&key={key}",
          _ok_no_marker("error_message"), "$5-10 per 1000 elements"),
    Probe("Find Place From Text", "GET",
          _M + "/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia"
               "&inputtype=textquery&fields=photos,formatted_address,name,rating,"
               "opening_hours,geometry&key={key}",
          _ok_no_marker("error_message"), "$17 per 1000 requests"),
    Probe("Places Autocomplete", "GET",
          _M + "/place/autocomplete/json?input=Bingh&types=%28cities%29&key={key}",
          _ok_no_marker("error_message"), "$2.83-17 per 1000 requests"),
    Probe("Elevation", "GET",
          _M + "/elevation/json?locations=39.7391536,-104.9847034&key={key}",
          _ok_no_marker("error_message"), "$5 per 1000 requests"),
    Probe("Time Zone", "GET",
          _M + "/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={key}",
          _ok_no_marker("errorMessage"), "$5 per 1000 requests"),
    Probe("Roads: Nearest Roads", "GET",
          _ROADS + "/nearestRoads?points=60.170880,24.942795|60.170879,24.942796"
                   "|60.170877,24.942796&key={key}",
          _ok_no_marker("error"), "$10 per 1000 requests"),
    Probe("Geolocation", "POST",
          "https://www.googleapis.com/geolocation/v1/geolocate?key={key}",
          _ok_no_marker("error"), "$5 per 1000 requests",
          body=json.dumps({"considerIp": "true"}), headers=_JSON),
    Probe("Roads: Snap to Roads", "GET",
          _ROADS + "/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907"
                   "&interpolate=true&key={key}",
          _ok_no_marker("error"), "$10 per 1000 requests"),
    Probe("Roads: Speed Limits", "GET",
          _ROADS + "/speedLimits?path=38.75807927603043,-9.03741754643809&key={key}",
          _ok_no_marker("error"), "$20 per 1000 requests"),
    Probe("Place Details", "GET",
          _M + "/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4"
               "&fields=name,rating,formatted_phone_number&key={key}",
          _ok_no_marker("error_message"), "$17 per 1000 requests"),
    Probe("Places Nearby Search", "GET",
          _M + "/place/nearbysearch/json?location=-33.8670522,151.1957362"
               "&radius=100&types=food&name=harbour&key={key}",
          _ok_no_marker("error_message"), "$32 per 1000 requests"),
    Probe("Places Text Search", "GET",
          _M + "/place/textsearch/json?query=restaurants+in+Sydney&key={key}",
          _ok_no_marker("error_message"), "$32 per 1000 requests"),
    Probe("Places Photo", "GET",
          _M + "/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4"
               "oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcH"
               "xYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3"
               "FyhNLlBU&key={key}",
          _redirect, "$7 per 1000 requests"),
    Probe("Address Validation", "POST",
          "https://addressvalidation.googleapis.com/v1:validateAddress?key={key}",
          _ok_no_marker("error"), "$5 per 1000 requests",
          body=json.dumps({"address": {"regionCode": "US", "addressLines": [
              "1600 Amphitheatre Pkwy, Mountain View, CA"]}}), headers=_JSON),
    Probe("Air Quality", "POST",
          "https://airquality.googleapis.com/v1/currentConditions:lookup?key={key}",
          _ok_no_marker("error"), "paid per request",
          body=json.dumps({"location": {"latitude": 37.419734, "longitude": -122.0827784}}),
          headers=_JSON),
    Probe("Aerial View", "GET",
          "https://aerialview.googleapis.com/v1/videos:lookupVideoMetadata?key={key}"
          "&address=600%20Montgomery%20St%2C%20San%20Francisco%2C%20CA%2094111",
          _ok_no_marker("error"), "paid per request"),
    Probe("Routes: computeRoutes", "POST",
          "https://routes.googleapis.com/directions/v2:computeRoutes?key={key}",
          lambda r: r.status == 200 and "error" not in r.body and "routes" in r.body,
          "paid per request", body=_ROUTES_BODY,
          headers=dict(_JSON, **{"X-Goog-FieldMask":
                                 "routes.duration,routes.distanceMeters,"
                                 "routes.polyline.encodedPolyline"})),
    Probe("Routes: computeRouteMatrix", "POST",
          "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key={key}",
          _ok_no_marker("error"), "paid per element", body=_ROUTES_MATRIX_BODY,
          headers=dict(_JSON, **{"X-Goog-FieldMask":
                                 "originIndex,destinationIndex,status,distanceMeters,duration"})),
    Probe("FCM (legacy send)", "POST", "https://fcm.googleapis.com/fcm/send",
          _json_200, "push-notification takeover (abss.me/posts/fcm-takeover)",
          body="{'registration_ids':['ABC']}", headers=_JSON, key_header=True,
          severity_bump=True),
    Probe("Gemini Files", "GET",
          "https://generativelanguage.googleapis.com/v1beta/files?key={key}",
          _json_200, "data exposure + paid model usage", severity_bump=True),
    Probe("Gemini Cached Contents", "GET",
          "https://generativelanguage.googleapis.com/v1beta/cachedContents?key={key}",
          _json_200, "data exposure + paid model usage", severity_bump=True),
]


@dataclass
class ProbeResult:
    probe: Probe
    accepted: bool
    status: int
    reason: str


def _reason(r: Resp) -> str:
    """Short human-readable rejection reason, from Google's error body."""
    if r.error:
        return r.error
    try:
        data = json.loads(r.body)
        if isinstance(data, list) and data and isinstance(data[0], dict):
            data = data[0]
        if isinstance(data, dict):
            for k in ("error_message", "errorMessage"):
                if isinstance(data.get(k), str):
                    return data[k][:200]
            err = data.get("error")
            if isinstance(err, dict):
                return str(err.get("message", err))[:200]
            if isinstance(err, str):
                return err[:200]
    except ValueError:
        pass
    return (r.body[:160].replace("\n", " ") or "HTTP %s" % r.status)


def run_probe(http, key: str, probe: Probe) -> ProbeResult:
    url = probe.url.replace("{key}", key)
    headers = dict(probe.headers or {})
    if probe.key_header:
        headers["Authorization"] = "key=" + key
    r = http.request(probe.method, url, headers=headers or None,
                     data=probe.body, infra=True, timeout=15.0)
    accepted = bool(r.status) and probe.judge(r)
    return ProbeResult(probe, accepted, r.status, "" if accepted else _reason(r))


def verify_key(http, key: str, stop: Optional[Callable[[], bool]] = None) -> List[ProbeResult]:
    out: List[ProbeResult] = []
    for probe in PROBES:
        if stop and stop():
            break
        out.append(run_probe(http, key, probe))
    return out


def poc_curl(probe: Probe, key: str) -> str:
    url = probe.url.replace("{key}", key)
    parts = ["curl -sS"]
    if probe.method == "POST":
        parts.append("-X POST")
    for k, v in (probe.headers or {}).items():
        parts.append("-H '%s: %s'" % (k, v))
    if probe.key_header:
        parts.append("-H 'Authorization: key=%s'" % key)
    if probe.body:
        parts.append("-d '%s'" % probe.body)
    parts.append("'%s'" % url)
    return " ".join(parts)


def jsapi_poc(key: str) -> str:
    """Manual check for the Maps JavaScript API: it only fails in a browser."""
    return ('<!DOCTYPE html><html><head><script src="https://maps.googleapis.com/maps/api/js'
            '?key=%s&callback=initMap&libraries=&v=weekly" defer></script>'
            '<style>#map{height:100%%;}html,body{height:100%%;margin:0;padding:0;}</style>'
            '<script>let map;function initMap(){map=new google.maps.Map('
            'document.getElementById("map"),{center:{lat:-34.397,lng:150.644},zoom:8});}'
            '</script></head><body><div id="map"></div></body></html>' % key)
