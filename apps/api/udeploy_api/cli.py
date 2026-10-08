"""`udeploy-admin`: idempotent bootstrap and maintenance commands."""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from sqlalchemy import select

from udeploy_security import pki
from udeploy_security.crypto import KeyRing
from udeploy_security.tokens import display_prefix, generate, hash_token

from .auth import Role
from .context import AppContext, registry_aad, webhook_aad
from .models import ApiToken, Membership, Organization, Registry, SecretValue, User, WebhookEndpoint
from .services.secrets import secret_aad
from .settings import get_settings


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def cmd_gen_master_key(_: argparse.Namespace) -> None:
    print(KeyRing.generate_entry())


def cmd_init_pki(args: argparse.Namespace) -> None:
    settings = get_settings()
    key_path, cert_path = settings.ca_key_path, settings.ca_cert_path
    if key_path.exists() and cert_path.exists():
        print(f"CA already present in {settings.pki_dir}")
    else:
        key_pem, cert_pem = pki.create_ca()
        _write_private(key_path, key_pem)
        cert_path.write_bytes(cert_pem)
        print(f"created CA in {settings.pki_dir}")
    server_crt = settings.pki_dir / "agent-api.crt"
    if server_crt.exists() and not args.force_server_cert:
        print("agent API server certificate already present")
        return
    key_pem, cert_pem = pki.issue_server_cert(
        key_path.read_bytes(), cert_path.read_bytes(), args.server_name, ips=args.server_ip
    )
    _write_private(settings.pki_dir / "agent-api.key", key_pem)
    server_crt.write_bytes(cert_pem)
    print(f"issued agent API server certificate for {args.server_name + args.server_ip}")


def cmd_migrate(_: argparse.Namespace) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parents[3] / "alembic.ini"))
    if not Path(cfg.config_file_name or "").exists():
        cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")


async def _bootstrap(args: argparse.Namespace) -> None:
    ctx = AppContext.from_settings(get_settings(), null_pool=True)
    async with ctx.db.session() as s:
        org = await s.scalar(select(Organization).where(Organization.slug == args.org))
        if org is None:
            org = Organization(
                slug=args.org, name=args.org_name or args.org, allowed_domains=sorted(set(args.domain))
            )
            s.add(org)
            print(f"created organization {args.org}")
        elif args.domain:
            org.allowed_domains = sorted(set(org.allowed_domains or []) | set(args.domain))
        user = await s.scalar(select(User).where(User.email == args.email.lower()))
        if user is None:
            user = User(email=args.email.lower(), display_name=args.email)
            s.add(user)
            print(f"created user {args.email}")
        await s.flush()
        member = await s.scalar(
            select(Membership).where(
                Membership.user_id == user.id,
                Membership.organization_id == org.id,
                Membership.project_id.is_(None),
            )
        )
        if member is None:
            s.add(Membership(user_id=user.id, organization_id=org.id, role=args.role))
        has_token = await s.scalar(
            select(ApiToken).where(ApiToken.user_id == user.id, ApiToken.revoked_at.is_(None))
        )
        token = None
        if has_token is None or args.new_token:
            token = generate("user")
            s.add(
                ApiToken(
                    user_id=user.id,
                    name="bootstrap",
                    token_hash=hash_token(token),
                    prefix=display_prefix(token),
                )
            )
        await s.commit()
        print(f"organization_id={org.id}")
        if token:
            print(f"api_token={token}   (shown once)")
        else:
            print("an active token already exists (use --new-token to issue another)")
    await ctx.db.dispose()


async def _rotate(_: argparse.Namespace) -> None:
    ctx = AppContext.from_settings(get_settings(), null_pool=True)
    box = ctx.box
    count = 0
    async with ctx.db.session() as s:
        for sec in (await s.scalars(select(SecretValue).with_for_update())).all():
            if box.needs_rotation(sec.ciphertext):
                aad = secret_aad(sec.organization_id, sec.project_id, sec.environment_id, sec.path)
                sec.ciphertext = box.encrypt(box.decrypt(sec.ciphertext, aad), aad)
                count += 1
        for reg in (await s.scalars(select(Registry).with_for_update())).all():
            if reg.password_ciphertext and box.needs_rotation(reg.password_ciphertext):
                aad = registry_aad(reg)
                reg.password_ciphertext = box.encrypt(box.decrypt(reg.password_ciphertext, aad), aad)
                count += 1
        for ep in (await s.scalars(select(WebhookEndpoint).with_for_update())).all():
            for field, name in (("secret_ciphertext", "secret"), ("signing_secret_ciphertext", "signing")):
                value = getattr(ep, field)
                if value and box.needs_rotation(value):
                    aad = webhook_aad(ep.id, name)
                    setattr(ep, field, box.encrypt(box.decrypt(value, aad), aad))
                    count += 1
        await s.commit()
    await ctx.db.dispose()
    print(f"re-encrypted {count} values with the active key; old keys can now be removed")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="udeploy-admin")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-master-key", help="print a new `kid:base64` master key entry").set_defaults(
        fn=cmd_gen_master_key
    )
    p = sub.add_parser("init-pki", help="create the internal CA and the agent API server certificate")
    p.add_argument("--server-name", action="append", required=True, help="DNS name agents use (repeatable)")
    p.add_argument("--server-ip", action="append", default=[], help="IP SAN (repeatable)")
    p.add_argument("--force-server-cert", action="store_true")
    p.set_defaults(fn=cmd_init_pki)
    sub.add_parser("migrate", help="apply database migrations").set_defaults(fn=cmd_migrate)
    p = sub.add_parser("bootstrap", help="create organization + owner + API token (idempotent)")
    p.add_argument("--org", required=True)
    p.add_argument("--org-name")
    p.add_argument("--email", required=True)
    p.add_argument("--role", default=Role.OWNER.value, choices=[r.value for r in Role])
    p.add_argument("--domain", action="append", default=[], help="domain suffix routes may use (repeatable)")
    p.add_argument("--new-token", action="store_true")
    p.set_defaults(fn=lambda a: asyncio.run(_bootstrap(a)))
    sub.add_parser("rotate-master-key", help="re-encrypt all values with the active key").set_defaults(
        fn=lambda a: asyncio.run(_rotate(a))
    )
    args = parser.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
