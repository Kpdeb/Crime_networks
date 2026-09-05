"""
Location Geodata
==================
Approximate latitude/longitude for locations that appear in the case data.
Used to plot a geographic heat map without depending on an external map-tile
service (which may be blocked on restricted networks) — coordinates are
rendered onto a bundled, stylized India outline instead of live map tiles.
"""

LOCATION_COORDS = {
    "Kolkata": (22.5726, 88.3639),
    "Howrah": (22.5958, 88.2636),
    "Salt Lake": (22.5850, 88.4200),
    "Sealdah": (22.5675, 88.3705),
    "Barasat": (22.7248, 88.4790),
    "Delhi": (28.7041, 77.1025),
    "Lajpat Nagar": (28.5677, 77.2433),
    "Paharganj": (28.6448, 77.2167),
}
