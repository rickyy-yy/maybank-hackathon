import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.database import engine

async def create_table():
    async with engine.begin() as conn:
        # Execute each statement separately
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS system_settings (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                setting_key VARCHAR(100) NOT NULL UNIQUE,
                setting_value TEXT,
                setting_type VARCHAR(50) NOT NULL,
                category VARCHAR(50) NOT NULL,
                description TEXT,
                is_sensitive BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_system_settings_key ON system_settings(setting_key)
        """))
        
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_system_settings_category ON system_settings(category)
        """))
        
    print("✅ Table and indexes created successfully!")

if __name__ == "__main__":
    asyncio.run(create_table())