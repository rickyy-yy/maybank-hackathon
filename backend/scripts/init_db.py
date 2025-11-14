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
    print("Initializing database...")

    try:
        async with engine.begin() as conn:
            # Drop all tables
            print("Dropping existing tables...")
            await conn.run_sync(Base.metadata.drop_all)
            print("✅ Dropped existing tables")

            # Create all tables
            print("Creating new tables...")
            await conn.run_sync(Base.metadata.create_all)
            print("✅ Created all tables")

        print("\n🎉 Database initialized successfully!")
        print("\nTables created:")
        print("  - scans")
        print("  - findings")
        print("  - remediation_templates")
        print("\nNext step: Run 'python scripts/load_templates.py' to load remediation templates")

    except Exception as e:
        print(f"\n❌ Error initializing database: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(init_db())