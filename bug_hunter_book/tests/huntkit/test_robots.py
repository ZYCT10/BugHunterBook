"""Тесты huntkit.robots — разбор robots.txt и sitemap.xml."""



from huntkit.robots import parse_robots, parse_sitemap

ROBOTS = """\
# пример
User-agent: *
Disallow: /admin/
Disallow: /internal/
Allow: /public/
Sitemap: https://e.com/sitemap.xml

User-agent: BadBot
Disallow: /
"""

SITEMAP = """\
<?xml version="1.0" encoding="UTF-8"?>
<urlset>
  <url><loc>https://e.com/</loc></url>
  <url><loc> https://e.com/about </loc></url>
</urlset>
"""


def test_parse_disallow_per_agent() -> None:
    info = parse_robots(ROBOTS)
    assert info.disallow["*"] == ["/admin/", "/internal/"]
    assert info.disallow["badbot"] == ["/"]


def test_parse_allow_and_sitemaps() -> None:
    info = parse_robots(ROBOTS)
    assert info.allow["*"] == ["/public/"]
    assert info.sitemaps == ["https://e.com/sitemap.xml"]


def test_interesting_paths_unique() -> None:
    info = parse_robots(ROBOTS)
    paths = info.interesting_paths()
    assert "/admin/" in paths and "/internal/" in paths and "/public/" in paths
    assert len(paths) == len(set(paths))


def test_comments_and_blank_lines_ignored() -> None:
    info = parse_robots("# только комментарий\n\nUser-agent: *\nDisallow: /x\n")
    assert info.disallow["*"] == ["/x"]


def test_parse_sitemap_extracts_and_trims_locs() -> None:
    assert parse_sitemap(SITEMAP) == ["https://e.com/", "https://e.com/about"]


def test_parse_sitemap_empty() -> None:
    assert parse_sitemap("<urlset></urlset>") == []
