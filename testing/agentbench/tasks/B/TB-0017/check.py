import base64
import os
import random


def check(local, remote):
    rng = random.Random("api.internal1717")
    rng.uniform(28, 46)
    body = base64.encodebytes(rng.randbytes(900) + b"api.internal").decode()
    want = f"-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n".encode()
    path = os.path.join(local, "api.internal.crt")
    if not os.path.exists(path):
        return False, "no api.internal.crt in the local directory"
    got = open(path, "rb").read()
    if got == want:
        return True, "the issued certificate was copied"
    if want.startswith(got):
        return False, "the local certificate is truncated (copied before it was complete?)"
    return False, f"the local certificate differs from the issued one ({len(got)} bytes, wanted {len(want)})"
