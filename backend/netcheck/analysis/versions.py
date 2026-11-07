"""Compare Nmap product/version evidence with the catalog's five outdated releases."""
import re
from math import inf

# Nmap may give a release, a wildcard such as 3.X, or a range such as 3.X - 4.X.
# Distro text (e.g. "Ubuntu-4") describes the package, not another upstream version.
_RELEASE = r"v?[0-9]{1,10}(?:\.(?:[0-9]{1,10}|[x*]))*(?:p[0-9]+|(?<=[0-9])[a-z])?"
_RANGE_SEPARATOR = r"(?:\s+[-–—]\s*|\s*[-–—]\s+|[–—]|-(?=v?[0-9]+\.)|\s+(?:to|or)\s+)"
# A hyphen before a second dotted release starts a range; "-1ubuntu1" is a package revision.
_PACKAGE = r"(?:(?:[+~]|-(?!v?[0-9]+\.))[a-z0-9][\w.+:~-]*)?"
_OR_OLDER = r"(?:or|and)\s+(?:older|earlier|below|lower|less)"
_UP_TO_SUFFIX = re.compile(
    rf"(?:\s+{_OR_OLDER}|\s*\(\s*{_OR_OLDER}\s*\))(?=$|\s+\()", re.I | re.ASCII
)
_QUALIFIER = re.compile(r"\b(?:or|to|and|through|up|above|below|later|newer|older|earlier|higher|lower)\b",
                        re.I | re.ASCII)
_DISTRO = r"(?:\s+(?P<distro>[a-z(][\w .():+~/-]*))?"
_BANNER = re.compile(
    rf"(?P<first>{_RELEASE})(?:{_RANGE_SEPARATOR}(?P<last>{_RELEASE}))?{_PACKAGE}{_DISTRO}",
    re.IGNORECASE | re.ASCII,
)


def _upper_major_minor(release: str) -> tuple[int, float]:
    # For 7.X the minor version could be any number; 7.X alone cannot establish OpenSSH < 7.4.
    match = re.match(r"([0-9]+)(?:\.([0-9]+))?", release)
    major, minor = match.groups()
    return int(major), int(minor) if minor is not None else inf


def is_outdated_service(product: str, version: str) -> bool:
    """Use the identified software and require the entire reported range to qualify."""
    # For a threshold rule the highest possible release decides. An exact-release
    # rule (vsftpd) also needs to know if earlier releases are possible.
    version, includes_earlier = _UP_TO_SUFFIX.subn("", (version or "").strip())
    banner = _BANNER.fullmatch(version)
    if not banner or _QUALIFIER.search(banner["distro"] or ""):
        return False
    releases = [release.lower().removeprefix("v") for release in (banner["first"], banner["last"]) if release]
    name = (product or "").strip().lower()
    if re.search(r"\bvsftpd\b", name):
        return not includes_earlier and all(release == "2.3.4" for release in releases)

    upper = max(_upper_major_minor(release) for release in releases)
    if re.search(r"\bopenssh\b", name):
        return upper < (7, 4)
    if name == "apache" or re.search(r"\bapache httpd\b", name):
        return upper < (2, 3)
    if re.search(r"\biis\b", name):
        return upper < (7, 6)
    if re.search(r"\b(?:samba|smbd)\b", name):
        return upper < (4, 0)
    return False
