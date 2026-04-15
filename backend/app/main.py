from fastapi import FastAPI
from typing import List

from app.db import init_db
from app.models import EventIn, ScenarioRunRequest
from app.services.event_service import save_event, list_events
from app.services.scenario_service import (
    run_scenario,
    get_scenario_status,
    list_scenarios,
    list_scenario_runs,
    list_running_scenario_runs,
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


# 공격 시나리오 실행
@app.post("/scenario/run")
def run_scenario_api(req: ScenarioRunRequest):
    return run_scenario(req)
    

@app.get("/scenario/status/{run_id}")
def scenario_status(run_id: str):
    return get_scenario_status(run_id)

    
@app.get("/scenario/list")
def scenario_list():
    return list_scenarios()


@app.get("/scenario-runs")
def scenario_runs(limit: int = 5):
    return list_scenario_runs(limit)
    

@app.get("/scenario-runs/running")
def scenario_runs_running():
    return list_running_scenario_runs()