import json

import hashlib

import redis

import requests

import logging

import uuid

from fastapi import FastAPI, HTTPException, Header, Response, Depends

from fastapi.responses import JSONResponse

from fastapi.security import OAuth2PasswordBearer

from jsonschema import validate, ValidationError

from pydantic import BaseModel, RootModel

from typing import Optional
 
# Load JSON schema

with open("schema.json") as f:

    SCHEMA = json.load(f)
 
# Initialize Redis client

redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)
 
# Initialize FastAPI app

app = FastAPI(version="v1")
 
# OAuth2PasswordBearer for token retrieval

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
 
# Pydantic model for dynamic JSON handling

class JSONPayload(RootModel):

    root: dict
 
# Function to generate ETag

def generate_etag(data: dict) -> str:

    return hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()
 
# Expected client ID (audience) for token verification

EXPECTED_AUDIENCE = "759863076238-sqhqicjs57hq4d50cd189njhg04pt33f.apps.googleusercontent.com"  # Replace with your actual client ID
 
def verify_token(token: str) -> dict:

    try:

        print(f"Starting token verification for: {token[:20]}...")

        google_public_keys_url = "https://www.googleapis.com/oauth2/v3/certs"

        response = requests.get(google_public_keys_url)

        if response.status_code != 200:

            raise HTTPException(status_code=500, detail=f"Failed to fetch Google public keys, status code: {response.status_code}")

        google_public_keys = response.json()

        if "keys" not in google_public_keys:

            raise HTTPException(status_code=500, detail="No 'keys' found in Google response")

        public_key = google_public_keys["keys"][0]

        print(f"Using public key for validation: {public_key}")

        from jose import jwt as jose_jwt, JWTError  # local import to avoid potential circular issues

        payload = jose_jwt.decode(token, public_key, algorithms=["RS256"], audience=EXPECTED_AUDIENCE, options={"verify_at_hash": False})

        print(f"Decoded JWT payload: {payload}")

        return payload

    except JWTError as e:

        logging.error(f"JWT decode error: {e}")

        raise HTTPException(status_code=401, detail="Invalid token")

    except requests.exceptions.RequestException as e:

        logging.error(f"Error fetching Google public keys: {e}")

        raise HTTPException(status_code=500, detail="Error fetching public keys from Google")

    except Exception as e:

        logging.error(f"Unexpected error: {str(e)}")

        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
 
# Function to validate string fields (ensures they are non-empty)

def validate_strings(payload: dict):

    required_string_fields = ["_org", "objectId", "objectType"]

    for field in required_string_fields:

        if field in payload:

            if not isinstance(payload[field], str) or payload[field].strip() == "":

                raise HTTPException(status_code=400, detail=f"Invalid value for '{field}': must be a non-empty string")

        else:

            raise HTTPException(status_code=400, detail=f"Missing required field '{field}'")

    if "linkedPlanServices" in payload:

        for service in payload["linkedPlanServices"]:

            validate_strings(service)

            if "linkedService" in service:

                validate_strings(service["linkedService"])

            if "planserviceCostShares" in service:

                validate_strings(service["planserviceCostShares"])
 
# Function to ensure all checklist criteria are met

def validate_checklist(payload: dict):

    checklist = {

        "_org": lambda x: isinstance(x, str) and x.strip() != "",

        "objectId": lambda x: isinstance(x, str) and x.strip() != "",

        "objectType": lambda x: isinstance(x, str) and x.strip() != "",

        "linkedPlanServices": lambda x: isinstance(x, list) and all(isinstance(service, dict) for service in x),

    }

    for field, check in checklist.items():

        if field in payload:

            if not check(payload[field]):

                raise HTTPException(status_code=400, detail=f"Invalid value for '{field}'")

        else:

            raise HTTPException(status_code=400, detail=f"Missing required field '{field}'")
 
# POST: Create a new plan in Redis

@app.post("/v1/plans", status_code=201)

def create_plan(payload: JSONPayload, token: str = Depends(oauth2_scheme)):

    try:

        verify_token(token)

        plan_id = payload.root["objectId"]

        if redis_client.exists(plan_id):

            raise HTTPException(status_code=400, detail="Plan with this ID already exists")

        validate(instance=payload.root, schema=SCHEMA)

        validate_strings(payload.root)

        validate_checklist(payload.root)

        etag = generate_etag(payload.root)

        redis_client.set(plan_id, json.dumps(payload.root))

        return JSONResponse(

            status_code=201,

            content={"message": "Plan created successfully", "id": plan_id, "body": payload.root},

            headers={"ETag": etag}

        )

    except ValidationError as e:

        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e.message}")

    except HTTPException as e:

        raise e

    except Exception as e:

        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")
 
# GET: Retrieve a health plan with conditional ETag support

@app.get("/v1/plans/{id}")

def get_plan(id: str, if_none_match: Optional[str] = Header(None), token: str = Depends(oauth2_scheme)):

    try:

        verify_token(token)

        plan_json = redis_client.get(id)

        if not plan_json:

            raise HTTPException(status_code=404, detail="Plan not found")

        plan_data = json.loads(plan_json)

        etag = generate_etag(plan_data)

        if if_none_match == etag:

            return Response(status_code=304)

        return Response(content=plan_json, media_type="application/json", headers={"ETag": etag})

    except Exception as e:

        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")
 
# PATCH: Update an existing plan (Merge updates and append new plan service objects)

@app.patch("/v1/plans/{id}")

def patch_plan(id: str, payload: JSONPayload, if_match: Optional[str] = Header(None), token: str = Depends(oauth2_scheme)):

    """Merge updates into an existing health plan and append new plan service objects as distinct entries."""
    print("Hello world")

    try:

        verify_token(token)

        if not if_match:

            raise HTTPException(status_code=400, detail="Bad Request: If-Match header is required")

        existing_plan_json = redis_client.get(id)

        if not existing_plan_json:

            raise HTTPException(status_code=404, detail="Plan not found")

        existing_plan = json.loads(existing_plan_json)

        etag = generate_etag(existing_plan)

        if if_match.strip().lower() != etag.strip().lower():

            raise HTTPException(status_code=412, detail="Precondition Failed: ETag mismatch")

        # Start with a copy of the existing plan

        updated_plan = existing_plan.copy()

        # Update each key from the payload; handle linkedPlanServices specially.

        for key, value in payload.root.items():

            if key == "linkedPlanServices":

                if not isinstance(value, list):

                    raise HTTPException(status_code=400, detail="Bad Request: linkedPlanServices must be a list")

                existing_services = existing_plan.get("linkedPlanServices", [])

                # Build a set of existing plan service objectIds for reference

                existing_ids = {service.get("objectId") for service in existing_services}

                new_services = []

                for service in value:

                    # If the incoming service's objectId already exists, generate a new unique id

                    if "objectId" in service and service["objectId"] in existing_ids:

                        service["objectId"] = str(uuid.uuid4())

                    new_services.append(service)

                # Append new services to the existing ones.

                updated_plan["linkedPlanServices"] = existing_services + new_services

            else:

                updated_plan[key] = value

        # Validate the updated plan against schema and custom validations.

        validate(instance=updated_plan, schema=SCHEMA)

        validate_strings(updated_plan)

        validate_checklist(updated_plan)

        # Store the updated plan in Redis.

        redis_client.set(id, json.dumps(updated_plan))

        return {"message": "Plan updated successfully", "body": updated_plan}

    except HTTPException:

        raise

    except Exception as e:

        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")
 
# DELETE: Delete a health plan from Redis

@app.delete("/v1/plans/{id}")

def delete_plan(id: str, token: str = Depends(oauth2_scheme)):

    try:

        verify_token(token)

        plan_json = redis_client.get(id)

        if not plan_json:

            raise HTTPException(status_code=404, detail="Plan not found")

        redis_client.delete(id)

        return {"message": "Deleted successfully"}

    except Exception as e:

        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

 