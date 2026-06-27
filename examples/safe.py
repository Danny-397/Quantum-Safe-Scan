"""Shows inline suppression: a finding can be silenced with a trailing marker."""

import hashlib

# This MD5 is only used as a non-security cache key, so we accept the risk:
cache_key = hashlib.md5(b"cache-input").hexdigest()  # quantumsafe: ignore

# This one is NOT suppressed and will be reported:
token = hashlib.md5(b"secret").hexdigest()
