#!/usr/bin/env python3
"""
Load sample remediation templates into database
"""

import asyncio
import json
from pathlib import Path
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.models.template import RemediationTemplate
from app.config import settings

async def load_templates():
    """Load remediation templates from JSON file"""
    
    # Create database engine
    engine = create_async_engine(settings.DATABASE_URL)
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    # Load templates from file
    templates_file = Path(__file__).parent.parent / "sample_data" / "remediation_templates.json"
    
    if not templates_file.exists():
        print(f"❌ Templates file not found: {templates_file}")
        return
    
    with open(templates_file, 'r') as f:
        templates_data = json.load(f)
    
    async with async_session() as session:
        # Clear existing templates
        await session.execute("DELETE FROM remediation_templates")
        
        # Insert new templates
        for template_data in templates_data:
            template = RemediationTemplate(**template_data)
            session.add(template)
        
        await session.commit()
        print(f"✅ Loaded {len(templates_data)} remediation templates")

if __name__ == "__main__":
    asyncio.run(load_templates())