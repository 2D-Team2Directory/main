from pydantic import BaseModel
from typing import Optional, Dict, Any


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

    # Sysmon 확장 필드
    image: Optional[str] = None
    command_line: Optional[str] = None
    parent_image: Optional[str] = None
    parent_command_line: Optional[str] = None
    current_directory: Optional[str] = None
    user: Optional[str] = None
    
    # Sysmon Network Connection
    destination_ip: Optional[str] = None
    destination_port: Optional[str] = None
    source_port: Optional[str] = None
    protocol: Optional[str] = None

    # Sysmon Image Loaded
    image_loaded: Optional[str] = None
    signed: Optional[str] = None
    signature_status: Optional[str] = None
    hashes: Optional[str] = None

    # Sysmon File Create
    target_filename: Optional[str] = None
    creation_utc_time: Optional[str] = None

    # Sysmon Registry Create/Delete
    target_object: Optional[str] = None
    registry_event_type: Optional[str] = None
    details: Optional[str] = None

    # Sysmon DNS Query
    query_name: Optional[str] = None
    query_status: Optional[str] = None
    query_results: Optional[str] = None


class ScenarioRunRequest(BaseModel):
    scenario_id: str
    params: Optional[Dict[str, Any]] = None