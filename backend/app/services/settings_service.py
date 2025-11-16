from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional, Dict, Any
import logging
import json

from app.models.settings import SystemSettings

logger = logging.getLogger(__name__)


class SettingsService:
    """Service for managing system settings stored in database"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_setting(self, key: str) -> Optional[Any]:
        """Get a single setting value by key"""
        result = await self.db.execute(
            select(SystemSettings).where(SystemSettings.setting_key == key)
        )
        setting = result.scalar_one_or_none()

        if not setting:
            return None

        return self._parse_value(setting.setting_value, setting.setting_type)

    async def get_settings_by_category(self, category: str) -> Dict[str, Any]:
        """Get all settings for a category"""
        result = await self.db.execute(
            select(SystemSettings).where(SystemSettings.category == category)
        )
        settings = result.scalars().all()

        return {
            setting.setting_key: self._parse_value(setting.setting_value, setting.setting_type)
            for setting in settings
        }

    async def set_setting(
        self,
        key: str,
        value: Any,
        setting_type: str = "string",
        category: str = "general",
        description: str = None,
        is_sensitive: bool = False
    ) -> SystemSettings:
        """Set or update a setting"""
        # Check if setting exists
        result = await self.db.execute(
            select(SystemSettings).where(SystemSettings.setting_key == key)
        )
        setting = result.scalar_one_or_none()

        # Convert value to string for storage
        str_value = self._stringify_value(value, setting_type)

        if setting:
            # Update existing
            setting.setting_value = str_value
            setting.setting_type = setting_type
            setting.category = category
            if description:
                setting.description = description
            setting.is_sensitive = is_sensitive
        else:
            # Create new
            setting = SystemSettings(
                setting_key=key,
                setting_value=str_value,
                setting_type=setting_type,
                category=category,
                description=description,
                is_sensitive=is_sensitive
            )
            self.db.add(setting)

        await self.db.commit()
        await self.db.refresh(setting)

        logger.info(f"Setting updated: {key}")
        return setting

    async def delete_setting(self, key: str) -> bool:
        """Delete a setting"""
        result = await self.db.execute(
            select(SystemSettings).where(SystemSettings.setting_key == key)
        )
        setting = result.scalar_one_or_none()

        if setting:
            await self.db.delete(setting)
            await self.db.commit()
            logger.info(f"Setting deleted: {key}")
            return True

        return False

    async def get_jira_config(self) -> Dict[str, Optional[str]]:
        """Get Jira configuration settings"""
        jira_settings = await self.get_settings_by_category("jira")

        return {
            "jira_url": jira_settings.get("jira_url"),
            "jira_email": jira_settings.get("jira_email"),
            "jira_api_token": jira_settings.get("jira_api_token"),
            "jira_project_key": jira_settings.get("jira_project_key"),
            "jira_enabled": jira_settings.get("jira_enabled", False)
        }

    async def save_jira_config(
        self,
        jira_url: Optional[str] = None,
        jira_email: Optional[str] = None,
        jira_api_token: Optional[str] = None,
        jira_project_key: Optional[str] = None,
        jira_enabled: bool = False
    ) -> Dict[str, Any]:
        """Save Jira configuration settings"""
        settings = {}

        if jira_url is not None:
            settings["jira_url"] = await self.set_setting(
                "jira_url", jira_url, "string", "jira",
                "Jira instance URL", False
            )

        if jira_email is not None:
            settings["jira_email"] = await self.set_setting(
                "jira_email", jira_email, "string", "jira",
                "Jira account email", False
            )

        if jira_api_token is not None:
            settings["jira_api_token"] = await self.set_setting(
                "jira_api_token", jira_api_token, "string", "jira",
                "Jira API token", True
            )

        if jira_project_key is not None:
            settings["jira_project_key"] = await self.set_setting(
                "jira_project_key", jira_project_key, "string", "jira",
                "Default Jira project key", False
            )

        settings["jira_enabled"] = await self.set_setting(
            "jira_enabled", jira_enabled, "boolean", "jira",
            "Enable Jira integration", False
        )

        return {
            "success": True,
            "message": "Jira settings saved successfully"
        }

    def _parse_value(self, value: str, setting_type: str) -> Any:
        """Parse stored string value to appropriate type"""
        if value is None:
            return None

        if setting_type == "boolean":
            return value.lower() in ("true", "1", "yes")
        elif setting_type == "integer":
            return int(value)
        elif setting_type == "json":
            return json.loads(value)
        else:  # string
            return value

    def _stringify_value(self, value: Any, setting_type: str) -> str:
        """Convert value to string for storage"""
        if value is None:
            return None

        if setting_type == "json":
            return json.dumps(value)
        elif setting_type == "boolean":
            return "true" if value else "false"
        else:
            return str(value)