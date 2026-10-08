from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from .settings import Settings


class Database:
    def __init__(self, url: str, *, null_pool: bool = False) -> None:
        kwargs: dict[str, object] = {"pool_pre_ping": True}
        if null_pool:
            kwargs = {"poolclass": NullPool}
        self.engine: AsyncEngine = create_async_engine(url, **kwargs)
        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False)

    @classmethod
    def from_settings(cls, settings: Settings, *, null_pool: bool = False) -> Database:
        return cls(settings.database_url, null_pool=null_pool)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.sessionmaker() as session:
            try:
                yield session
            except BaseException:
                await session.rollback()
                raise

    async def dispose(self) -> None:
        await self.engine.dispose()
