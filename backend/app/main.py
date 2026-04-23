from fastapi import FastAPI,  HTTPException
from typing import List

from app.db import init_db
from app.models import EventIn, ScenarioRunRequest
from app.services.event_service import (
    save_event, 
    list_events,
    delete_all_events,
    delete_event_by_id,
)
from app.services.scenario_service import (
    run_scenario,
    get_scenario_status,
    list_scenarios,
    list_scenario_runs,
    list_running_scenario_runs,
    get_scenario_log,
)


app = FastAPI()

@app.on_event("startup")
def startup():
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/events")
def ingest_event(event: EventIn):
    return save_event(event)


@app.get("/events")
def get_events(limit: int = 50):
    return list_events(limit)


@app.delete("/events")
def delete_events_all():
    return delete_all_events()


@app.delete("/events/{event_row_id}")
def delete_single_event(event_row_id: int):
    result = delete_event_by_id(event_row_id)
    if result.get("result") == "not_found":
        raise HTTPException(status_code=404, detail="Event not found")
    return result


# 공격 시나리오 실행
@app.post("/scenario/run")
def run_scenario_api(req: ScenarioRunRequest):
    return run_scenario(req)
    

@app.get("/scenario/status/{run_id}")
def scenario_status(run_id: str):
    return get_scenario_status(run_id)


@app.get("/scenario/log/{run_id}")
def scenario_log(run_id: str, tail: int = 200):
    return get_scenario_log(run_id, tail=tail)
    

@app.get("/scenario/list")
def scenario_list():
    return list_scenarios()


@app.get("/scenario-runs")
def scenario_runs(limit: int = 5):
    return list_scenario_runs(limit)
    

@app.get("/scenario-runs/running")
def scenario_runs_running():
    return list_running_scenario_runs()