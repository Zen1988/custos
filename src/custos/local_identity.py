"""Local account provisioning and password verification; no HTTP login session yet."""
import base64
import hashlib
import hmac
import secrets

from sqlalchemy import select

from custos.database import LocalCredential, Principal


def password_hash(password):
    if not 12 <= len(password) <= 1024:
        raise ValueError("Local passwords must contain 12 to 1024 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password, encoded):
    try:
        scheme, n, r, p, salt, digest = encoded.split("$")
        if scheme != "scrypt" or (n, r, p) != ("16384", "8", "1") or len(password) > 1024:
            return False
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt, validate=True),
                                n=16384, r=8, p=1, dklen=32)
        return hmac.compare_digest(actual, base64.b64decode(digest, validate=True))
    except (ValueError, TypeError):
        return False


def create_local_user(session, username, display_name, password):
    username = username.strip().casefold()
    if not username or len(username) > 200 or not display_name.strip():
        raise ValueError("A local username and display name are required")
    if session.scalar(select(LocalCredential).where(LocalCredential.username == username)):
        raise ValueError("Local username already exists")
    encoded = password_hash(password)
    user = Principal(directory_id=None, external_id="local:" + secrets.token_hex(16),
                     kind="user", display_name=display_name.strip(), enabled=True)
    session.add(user)
    session.flush()
    session.add(LocalCredential(principal_id=user.id, username=username, password_hash=encoded))
    return user


_DUMMY_HASH = password_hash(secrets.token_urlsafe(32))


def authenticate_local(session, username, password):
    credential = session.scalar(select(LocalCredential).where(
        LocalCredential.username == username.strip().casefold()))
    valid = verify_password(password, credential.password_hash if credential else _DUMMY_HASH)
    if not credential or not valid:
        return None
    user = session.get(Principal, credential.principal_id)
    if not user or not user.enabled or user.kind != "user" or user.directory_id is not None:
        return None
    return user
