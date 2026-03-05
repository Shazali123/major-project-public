"""
GoPhish Diagnostic Script  v2
Tests: connectivity, resource listing, AND a live campaign creation attempt.
Usage: python gophish_diag.py
"""

import json, ssl, urllib.request, urllib.error, os, sys, datetime, time

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'modules', 'module_2_gophish', 'gophish_config.json')

def load_cfg():
    with open(CONFIG_PATH) as f:
        return json.load(f)

def req(host, api_key, path, method='GET', data=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = f"{host}/api{path}?api_key={api_key}"
    body = json.dumps(data).encode() if data else None
    r = urllib.request.Request(url, data=body, method=method)
    r.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        body_err = e.read().decode()
        print(f"  HTTP {e.code}: {body_err}")
        return e.code, {}
    except Exception as e:
        print(f"  EXCEPTION: {type(e).__name__}: {e}")
        return 0, {}

def get_list(host, key, path):
    code, data = req(host, key, path)
    if code != 200:
        return []
    if isinstance(data, list):
        return data
    for k in ('data', 'results', 'items'):
        if isinstance(data.get(k), list):
            return data[k]
    return []

def find(items, name):
    for i in items:
        if isinstance(i, dict) and i.get('name', '').lower() == name.lower():
            return i
    return None

cfg = load_cfg()
HOST = cfg['host']
KEY  = cfg['api_key']

print("=" * 64)
print(f"GoPhish Diagnostic v2")
print(f"Host   : {HOST}")
print(f"APIKey : {KEY[:8]}...{KEY[-4:]}")
print("=" * 64)

# 1. Basic connectivity
print("\n[1] Connection (/api/campaigns/) ...")
code, data = req(HOST, KEY, '/campaigns/')
print(f"    Status: {code}")
if code != 200:
    print("    FAIL - cannot connect. Check host and API key.")
    sys.exit(1)
print(f"    OK - {len(data) if isinstance(data, list) else '?'} existing campaigns")

# 2. Resources
smtp_list = get_list(HOST, KEY, '/smtp/')
tpl_list  = get_list(HOST, KEY, '/templates/')
page_list = get_list(HOST, KEY, '/pages/')

print(f"\n[2] SMTP Profiles: {len(smtp_list)} found")
for s in smtp_list:
    print(f"    id={s.get('id')}  name='{s.get('name')}'  host={s.get('host')}")

print(f"\n[3] Email Templates: {len(tpl_list)} found")
for t in tpl_list:
    print(f"    id={t.get('id')}  name='{t.get('name')}'")

print(f"\n[4] Landing Pages: {len(page_list)} found")
for p in page_list:
    print(f"    id={p.get('id')}  name='{p.get('name')}'")

# 3. Name matching
print(f"\n[5] Config name matching...")
smtp = find(smtp_list, cfg.get('smtp_profile', ''))
tpl  = find(tpl_list,  cfg.get('email_template', ''))
page = find(page_list, cfg.get('landing_page', ''))
print(f"    Expected SMTP     : '{cfg.get('smtp_profile')}'  -> {'FOUND (id=' + str(smtp.get('id')) + ')' if smtp else 'MISSING'}")
print(f"    Expected Template : '{cfg.get('email_template')}'  -> {'FOUND (id=' + str(tpl.get('id')) + ')' if tpl else 'MISSING'}")
print(f"    Expected Page     : '{cfg.get('landing_page')}'  -> {'FOUND (id=' + str(page.get('id')) + ')' if page else 'MISSING'}")

if not (smtp and tpl and page):
    print("\n    STOP - fix missing resources first.")
    sys.exit(1)

# 4. Test group creation
print(f"\n[6] Test group creation...")
group_name = f"DIAG_Group_{int(time.time())}"
code, g = req(HOST, KEY, '/groups/', method='POST', data={
    'name': group_name,
    'targets': [{'first_name': 'Test', 'last_name': 'User',
                 'email': cfg.get('target_email', 'test@example.local'),
                 'position': 'Test'}]
})
print(f"    Status: {code}  id={g.get('id')}  name={g.get('name')}")
group_id = g.get('id')
if not group_id:
    print("    FAIL - cannot create group")
    sys.exit(1)
print("    OK")

# 5. Test campaign creation (the real test)
print(f"\n[7] Test campaign creation (with full id+name objects)...")
launch_time = (datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
               ).strftime('%Y-%m-%dT%H:%M:%S+00:00')
host_ip = HOST.split('://')[-1].split(':')[0]
phish_url = f"http://{host_ip}:{cfg.get('phish_port', 8081)}"

payload = {
    'name':        f"DIAG_Campaign_{int(time.time())}",
    'template':    {'name': tpl['name'], 'id': tpl['id']},
    'page':        {'name': page['name'], 'id': page['id']},
    'smtp':        {'name': smtp['name'], 'id': smtp['id']},
    'launch_date': launch_time,
    'url':         phish_url,
    'groups':      [{'name': group_name}],
}
print(f"    Payload:")
for k, v in payload.items():
    print(f"      {k}: {v}")

code, camp = req(HOST, KEY, '/campaigns/', method='POST', data=payload)
camp_id = camp.get('id')
print(f"\n    Status: {code}  campaign_id={camp_id}")

if code in (200, 201) and camp_id and camp_id > 0:
    print("    OK - campaign created successfully!")
    # Immediately complete and delete it
    req(HOST, KEY, f'/campaigns/{camp_id}/complete')
    req(HOST, KEY, f'/campaigns/{camp_id}', method='DELETE')
    print("    Cleaned up test campaign.")
else:
    print(f"    FAIL - response: {camp}")

# Cleanup group
req(HOST, KEY, f'/groups/{group_id}', method='DELETE')
print(f"\n    Test group '{group_name}' deleted.")

print("\n" + "=" * 64)
print("Diagnostic complete.")
print("=" * 64)
