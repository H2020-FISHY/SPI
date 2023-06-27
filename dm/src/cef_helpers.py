from requests import post
import json

def dict_without_empty_values(src_dict):
    return {k: v for k, v in src_dict.items() if len(str(v).strip()) > 0}

def build_cef(device_product, device_version, device_event_class_id, event_name, severity, extensions_list, pilot):
    return {
        "device_product": device_product,
        "device_version": str(device_version),
        "device_event_class_id": str(device_event_class_id),
        "event_name": event_name,
        "severity": str(severity),
        "extensions_list": json.dumps(dict_without_empty_values(extensions_list)),
        "pilot": pilot
    }

def http_post_cef(url, event):
    return post(url, json=event)
