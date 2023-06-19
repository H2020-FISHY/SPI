import shlex, secrets
from flask import Flask, request
from datetime import datetime
from os import environ
from cef_helpers import build_cef, http_post_cef
from functools import partial

print = partial(print, flush=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(16)

output_base_url = environ.get("OUTPUT_ENDPOINT_BASE_URL")
if output_base_url is None:
    print("Could not find OUTPUT_ENDPOINT_BASE_URL environment variable, exiting...")
    exit()
print("Output base url set to -> {}".format(str(output_base_url)))


def if_in_push(src_key, src_dict, dst_key, dst_dict):
    if src_key in src_dict:
        dst_dict[dst_key] = src_dict[src_key]

def dict_without_empty_values(src_dict):
    return {k: v for k, v in src_dict.items() if len(str(v).strip()) > 0}


@app.route("/api/normalize/zeek", methods=["POST"])
def normalize_zeek():
    try:
        event = request.get_json()
    except:
        return {"status": "error", "msg": "Invalid JSON"}, 400

    if len(event) == 0:
        return {"status": "error", "msg": "Missing body"}, 400

    try:
        extensions_list = {
            "ts": datetime.strptime(event["ts"].strip(), "%Y-%m-%dT%H:%M:%S.%fZ"),
            "msg": event["msg"],
            "suppressFor": event["suppress_for"],
        }

        cef_event = build_cef(
            device_product="Zeek",
            device_version="1.0",
            device_event_class_id="Unknown",  # Try to map this value
            event_name=event["note"],
            severity="Unknown",  # Try to map this value
            extensions_list=dict_without_empty_values(extensions_list),
        )

    except Exception as ex:
        print("Failed to normalize data: {}".format(str(ex)))
        return {"status": "error", "msg": "Invalid Data"}, 400

    try:
        response = http_post_cef(output_base_url, cef_event)
        if response.status_code == 201:
            return {
                "status": "success",
                "msg": "Data normalized & posted",
                "normalized_data": cef_event,
            }, 200
        else:
            return {"status": "error", "msg": "Failed to post normalized data"}, 400

    except Exception as ex:
        print("Failed to post data: {}".format(str(ex)))
        return {"status": "error", "msg": "Failed to post normalized data"}, 400


@app.route("/api/normalize/pmem", methods=["POST"])
def normalize_pmem():
    try:
        event_text = request.get_data(as_text=True)
        event = dict(s.split("=", 1) for s in shlex.split(event_text))
    except:
        return {"status": "error", "msg": "Invalid Text"}, 400

    if len(event) == 0:
        return {"status": "error", "msg": "Missing body"}, 400

    try:
        extensions_list = {
            "ts": datetime.strptime(event["TimeStamp"].strip(), "%d/%m/%Y %H:%M:%S"),
            "src": event["attackinIP"],
        }

        cef_event = build_cef(
            device_product="PMEM",
            device_version="1.0",
            device_event_class_id="Unknown",  # Try to map this value
            event_name=event["type"],
            severity="Unknown",  # Try to map this value
            extensions_list=dict_without_empty_values(extensions_list),
        )

    except Exception as ex:
        print("Failed to normalize data: {}".format(str(ex)))
        return {"status": "error", "msg": "Invalid Data"}, 400

    try:
        response = http_post_cef(output_base_url, cef_event)
        if response.status_code == 201:
            return {
                "status": "success",
                "msg": "Data normalized & posted",
                "normalized_data": cef_event,
            }, 200
        else:
            return {"status": "error", "msg": "Failed to post normalized data"}, 400

    except Exception as ex:
        print("Failed to post data: {}".format(str(ex)))
        return {"status": "error", "msg": "Failed to post normalized data"}, 400


@app.route("/api/normalize/trustmonitor", methods=["POST"])
def normalize_tm():
    try:
        event = request.get_json()
    except:
        return {"status": "error", "msg": "Invalid JSON"}, 400

    if len(event) == 0:
        return {"status": "error", "msg": "Missing body"}, 400

    try:
        extensions_list = {
            "entityId": event["entity_uuid"],
            "ts": datetime.strptime(event["time"].strip(), "%Y-%m-%d %H:%M:%S.%f"),
            "trustStatus": event["trust"],
            "trustState": str(event["state"]),
        }

        cef_event = build_cef(
            device_product="TrustMonitor",
            device_version="1.0",
            device_event_class_id="Unknown",  # Try to map this value
            event_name="Domain infrastructure integrity report",
            severity="Unknown",  # Try to map this value
            extensions_list=dict_without_empty_values(extensions_list),
        )

    except Exception as ex:
        print("Failed to normalize data: {}".format(str(ex)))
        return {"status": "error", "msg": "Invalid Data"}, 400

    try:
        response = http_post_cef(output_base_url, cef_event)
        if response.status_code == 201:
            return {
                "status": "success",
                "msg": "Data normalized & posted",
                "normalized_data": cef_event,
            }, 200
        else:
            return {"status": "error", "msg": "Failed to post normalized data"}, 400

    except Exception as ex:
        print("Failed to post data: {}".format(str(ex)))
        return {"status": "error", "msg": "Failed to post normalized data"}, 400


@app.route("/api/normalize/rae", methods=["POST"])
def normalize_rae():
    try:
        event = request.get_json()
    except:
        return {"status": "error", "msg": "Invalid JSON"}, 400

    if len(event) == 0:
        return {"status": "error", "msg": "Missing body"}, 400

    try:
        result = event["results"][0]

        extensions_list = {
            "id": result["id"],
            "ts": datetime.strptime(
                result["timestamp"].strip(), "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
            "qualRiskAssessment": result["overall_qualitative_assessment"],
            "quantRiskAssessment": str(result["overall_quantitative_assessment"]),
            "selectedRiskModels": str(result["selected_risk_models"]),
            "mitigationMeasures": str(result["mitigation_measures"]),
        }

        cef_event = build_cef(
            device_product="RAE",
            device_version="1.0",
            device_event_class_id="Unknown",  # Try to map this value
            event_name="Risk assessment",
            severity="Unknown",  # Try to map this value
            extensions_list=dict_without_empty_values(extensions_list),
        )

    except Exception as ex:
        print("Failed to normalize data: {}".format(str(ex)))
        return {"status": "error", "msg": "Invalid Data"}, 400

    try:
        response = http_post_cef(output_base_url, cef_event)
        if response.status_code == 201:
            return {
                "status": "success",
                "msg": "Data normalized & posted",
                "normalized_data": cef_event,
            }, 200
        else:
            return {"status": "error", "msg": "Failed to post normalized data"}, 400

    except Exception as ex:
        print("Failed to post data: {}".format(str(ex)))
        return {"status": "error", "msg": "Failed to post normalized data"}, 400


@app.route("/api/normalize/xl-siem", methods=["POST"])
def normalize_xl_siem():
    try:
        event = request.get_json()
    except:
        return {"status": "error", "msg": "Invalid JSON"}, 400

    if len(event) == 0:
        return {"status": "error", "msg": "Missing body"}, 400

    try:
        event = event["AlarmEvent"]

        extensions_list = {
            "ts": datetime.strptime(event["DATE"].strip(), "%Y-%m-%d %H:%M:%S"),
        }

        mappings = {
            "RELATED_EVENTS": "relEvents",
            "RELATED_EVENTS_INFO": "relEventsInfo",
            "PLUGIN_ID": "pluginId",
            "PLUGIN_NAME": "pluginName",
            "PLUGIN_SID": "pluginSid",
            "BACKLOG_ID": "backlogId",
            "SRC_IP": "src",
            "SRC_PORT": "spt",
            "SRC_IP_HOSTNAME": "shost",
            "DST_IP": "dst",
            "DST_PORT": "dpt",
            "DST_IP_HOSTNAME": "dhost",
            "USERNAME": "user",
            "PASSWORD": "pass",
            "SID_NAME": "sidName",
            "FILENAME": "fileName",
            "ORGANIZATION": "org",
            "RISK": "risk",
            "RELIABILITY": "reliability",
            "PROTOCOL": "proto",
            "CATEGORY": "category",
            "DESCRIPTION": "description",
            "SUBCATEGORY": "subcategory",
            "USERDATA1": "userData1",
            "USERDATA2": "userData2",
            "USERDATA3": "userData3",
            "USERDATA4": "userData4",
            "USERDATA5": "userData5",
            "USERDATA6": "userData6",
            "USERDATA7": "userData7",
            "USERDATA8": "userData8",
            "USERDATA9": "userData9",
        }

        for key in mappings:
            if_in_push(key, event, mappings[key], extensions_list)

        cef_event = build_cef(
            device_product="XL-SIEM",
            device_version="1.0",
            device_event_class_id="Unknown",
            event_name=(event["EVENT_ID"] if "EVENT_ID" in event else "Unknown"),
            severity=(event["PRIORITY"] if "PRIORITY" in event else "Unknown"),
            extensions_list=dict_without_empty_values(extensions_list),
        )

    except Exception as ex:
        print("Failed to normalize data: {}".format(str(ex)))
        return {"status": "error", "msg": "Invalid Data"}, 400

    try:
        response = http_post_cef(output_base_url, cef_event)
        if response.status_code == 201:
            return {
                "status": "success",
                "msg": "Data normalized & posted",
                "normalized_data": cef_event,
            }, 200
        else:
            return {"status": "error", "msg": "Failed to post normalized data"}, 400

    except Exception as ex:
        print("Failed to post data: {}".format(str(ex)))
        return {"status": "error", "msg": "Failed to post normalized data"}, 400
