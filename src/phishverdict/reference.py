"""Brand, shortener and risky-TLD reference data for phishverdict.

All lists are deliberately small and readable. They are heuristics, not
truth: extend them in your own fork for your environment.
"""

# name of brand -> canonical official registrable domain
BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "gmail": "gmail.com",
    "microsoft": "microsoft.com",
    "office": "office.com",
    "outlook": "outlook.com",
    "apple": "apple.com",
    "icloud": "icloud.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com",
    "twitter": "twitter.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "metamask": "metamask.io",
    "steam": "steampowered.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "usps": "usps.com",
    "irs": "irs.gov",
    "icici": "icicibank.com",
    "hdfc": "hdfcbank.com",
    "sbi": "sbi.co.in",
    "paytm": "paytm.com",
    "phonepe": "phonepe.com",
    "revolut": "revolut.com",
    "github": "github.com",
    "gitlab": "gitlab.com",
}

# hosts that hide the real destination
SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "rebrand.ly",
    "rb.gy", "shorturl.at", "ow.ly", "buff.ly", "goo.gl", "v.gd",
    "tiny.cc", "s.id", "tr.im", "clck.ru", "u.to", "bit.do", "t.ly",
    "shorturl.at", "tinyurl.com",
}

# TLDs with a poor reputation in phishing corpora (danger: heuristics!)
RISKY_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click",
    "country", "work", "rest", "sbs", "quest", "monster", "loan", "men",
    "party", "date", "faith", "review", "stream", "download", "buzz",
    "cam", "kim", "lol", "mom", "cfd", "icu", "surf", "bar",
}

# whole-label tokens (split on . and -) typical of phishing hostnames
LOGIN_TOKENS = {
    "login", "signin", "signon", "verify", "verification", "secure",
    "account", "update", "confirm", "wallet", "billing",
    "recovery", "recover", "unlock", "webmail", "webscr", "security",
    "support", "helpdesk", "manage", "portal",
}

# ccTLDs where the public suffix is two labels long
SECOND_LEVEL_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in",
    "ac.in", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp",
    "com.br", "com.mx", "co.nz", "com.tr", "com.cn", "com.sg", "co.za",
}

# single-character substitutions favoured by typosquatters
LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "9": "g", "@": "a", "$": "s",
})


def registrable_domain(host: str) -> str:
    """Approximate the registrable domain (no PSL dependency).

    >>> registrable_domain("bbc.co.uk")
    'bbc.co.uk'
    >>> registrable_domain("mail.google.com")
    'google.com'
    """
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL_TLDS:
        return ".".join(labels[-3:])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


def de_leet(text: str) -> str:
    """Undo common leetspeak substitutions and rn/vv ligature tricks."""
    t = text.translate(LEET_MAP)
    for ugly, real in (("rn", "m"), ("vv", "w")):
        t = t.replace(ugly, real)
    return t


def levenshtein(a: str, b: str, cap: int = 2) -> int:
    """Levenshtein distance with an early-exit cap."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]
