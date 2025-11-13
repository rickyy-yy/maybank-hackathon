import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import engine, Base
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.template import RemediationTemplate


async def init_db():
    """Initialize database by creating all tables"""
    async with engine.begin() as conn:
        # Drop all tables
        await conn.run_sync(Base.metadata.drop_all)
        print("✅ Dropped existing tables")

        # Create all tables
        await conn.run_sync(Base.metadata.create_all)
        print("✅ Created all tables")

    print("\n🎉 Database initialized successfully!")
    print("\nTables created:")
    print("  - scans")
    print("  - findings")
    print("  - remediation_templates")


if __name__ == "__main__":
    asyncio.run(init_db())