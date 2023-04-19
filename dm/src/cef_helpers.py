from requests import post

def escape_cef_header_str(str):
  return str.replace("\n", "").replace("\r", "").translate(str.maketrans({"\\":  r"\\", "|":  r"\|"}))

def escape_cef_extension_str(str):
    return str.translate(str.maketrans({"\\":  r"\\", "=":  r"\="}))

def build_cef_extension(extensions_keypairs):
  return ' '.join(list(map(lambda extension_key: "{}={}".format(
    escape_cef_extension_str(extension_key), 
    escape_cef_extension_str(str(extensions_keypairs[extension_key]))), extensions_keypairs)))

def build_cef(device_product, device_version, device_event_class_id, event_name, severity, extensions_list):
    return {
        "device_product": escape_cef_header_str(device_product),
        "device_version": escape_cef_header_str(str(device_version)),
        "device_event_class_id": escape_cef_header_str(str(device_event_class_id)),
        "event_name": escape_cef_header_str(event_name),
        "severity": escape_cef_header_str(str(severity)),
        "extensions_list": build_cef_extension(extensions_list)
    }

def http_post_cef(url, event):
    return post(url, json=event)
