from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional

from app.database import get_db
from app.services.settings_service import SettingsService
from app.services.jira_service import JiraIntegrationService

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


class JiraSettingsRequest(BaseModel):
    jira_url: Optional[str] = None
    jira_email: Optional[str] = None
    jira_api_token: Optional[str] = None
    jira_project_key: Optional[str] = None
    jira_enabled: bool = False


class JiraSettingsResponse(BaseModel):
    jira_url: Optional[str] = None
    jira_email: Optional[str] = None
    jira_api_token_set: bool = False  # Don't return actual token
    jira_project_key: Optional[str] = None
    jira_enabled: bool = False


@router.get("/jira")
async def get_jira_settings(db: AsyncSession = Depends(get_db)) -> JiraSettingsResponse:
    """Get current Jira settings"""
    settings_service = SettingsService(db)
    config = await settings_service.get_jira_config()

    return JiraSettingsResponse(
        jira_url=config.get("jira_url"),
        jira_email=config.get("jira_email"),
        jira_api_token_set=bool(config.get("jira_api_token")),
        jira_project_key=config.get("jira_project_key"),
        jira_enabled=config.get("jira_enabled", False)
    )


@router.post("/jira")
async def update_jira_settings(
    settings: JiraSettingsRequest,
    db: AsyncSession = Depends(get_db)
):
    """Update Jira settings"""
    settings_service = SettingsService(db)

    result = await settings_service.save_jira_config(
        jira_url=settings.jira_url,
        jira_email=settings.jira_email,
        jira_api_token=settings.jira_api_token,
        jira_project_key=settings.jira_project_key,
        jira_enabled=settings.jira_enabled
    )

    return result


@router.post("/jira/test")
async def test_jira_connection(db: AsyncSession = Depends(get_db)):
    """Test Jira connection with current settings"""
    settings_service = SettingsService(db)
    jira_config = await settings_service.get_jira_config()

    if not jira_config.get("jira_enabled"):
        raise HTTPException(status_code=400, detail="Jira integration is not enabled")

    jira_service = JiraIntegrationService(jira_config)

    if not jira_service.enabled:
        raise HTTPException(
            status_code=503,
            detail="Jira is not properly configured. Please check your settings."
        )

    try:
        connected = jira_service.test_connection()
        if connected:
            return {
                "success": True,
                "message": "Successfully connected to Jira"
            }
        else:
            return {
                "success": False,
                "message": "Failed to connect to Jira. Please check your credentials."
            }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Connection test failed: {str(e)}"
        )