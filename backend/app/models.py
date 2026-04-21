from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class EventIn(BaseModel):
    event_time: Optional[str] = None
    event_id: Optional[str] = None
    provider: Optional[str] = None
    channel: Optional[str] = None
    level: Optional[str] = None
    computer_name: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    target_host: Optional[str] = None
    group_name: Optional[str] = None
    logon_type: Optional[str] = None
    service_name: Optional[str] = None
    message: Optional[str] = None
    raw_json: Optional[str] = None


class ScenarioRunRequest(BaseModel):
    scenario_id: str
    params: Optional[Dict[str, Any]] = None