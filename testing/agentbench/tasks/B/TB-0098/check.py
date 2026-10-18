import os


def check(local, remote):
    p = os.path.join(remote, ".config", "gamesrv", "server.toml")
    if not os.path.exists(p):
        return False, "the wizard never saved ~/.config/gamesrv/server.toml"
    got = open(p).read()
    want = 'name = "ladder-eu-3"\nregion = "eu-west"\nmax_players = 48\n'
    return got == want, f"saved {got!r}, wanted {want!r}"
