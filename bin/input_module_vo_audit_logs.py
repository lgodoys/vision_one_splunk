# encoding = utf-8

import app_common as utils
import json
import requests
import datetime
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from urllib.parse import urlparse
from dateutil.parser import parse as date_parse

APP_VERSION = utils.get_version()

def result_format(helper, obj):
    try:
        if 'result' in obj:
            obj['result'] = 'Successful' if obj['result'] else 'Unsuccessful'
    except Exception as err:
        helper.log_error('[TrendMicro Audit] result field format error: %s'%(str(err)))

def user_format(helper,obj):
    try:
        if len(obj.get('loggedUser', '').strip()) == 0:
            obj['loggedUser'] = 'Root Account'
    except Exception as err:
        helper.log_error('[TrendMicro Audit] user field format error: %s'%(str(err)))

def role_format(helper,obj):
    try:
        if len(obj.get('loggedRole','').strip()) == 0:
            obj['loggedRole'] = 'Administrator'
    except Exception as err:
        helper.log_error('[TrendMicro Audit] role field format error: %s'%(str(err)))

def log_formater(helper,obj):
    formater = {
        'result': result_format,
        'loggedUser': user_format,
        'loggedRole': role_format,
        'loggedDateTime': iso_format
        }
    try:
        for handle in formater.values():
            handle(helper,obj)
    except Exception as err:
        helper.log_error('[TrendMicro Audit] audit log format error: %s'%(str(err)))
        
def iso_format(helper, obj):
    try:
        if 'loggedDateTime' in obj:
            obj['loggedDateTime'] = date_parse(obj['loggedDateTime']).isoformat()
    except Exception as err:
        helper.log_error('[TrendMicro Audit] loggedDateTime field format error: %s'%(str(err)))

def validate_input(helper, definition):
    global_account = definition.parameters.get('global_account', None)
    interval = definition.parameters.get('interval',None)
    if interval is not None and int(interval) < 10:
        raise ValueError('The minimum public API access interval cannot be less than 10 seconds')

def collect_events(helper, ew):
    STANZA = helper.get_input_stanza_names()
    polling = helper.get_arg('interval')
    token = helper.get_arg('global_account')['password']
    backoff_time = float(helper.get_global_setting("backoff_time") or 10)
    endpoint = helper.get_arg('global_account')['url']
    
    if (not endpoint) or (not token):
        helper.log_info("[TrendMicro Audit] no valid config, will pass")
        return 0

    cid = utils.extractCID(token)

    parse_url = urlparse(endpoint)
    if not "https" in  parse_url.scheme:
        return 0
    else:
        endpoint = "{}://{}".format(parse_url.scheme, parse_url.netloc)
        helper.log_info("[TrendMicro Audit] get endpoint: %s" % endpoint)

    url_path = '/v3.0/audit/logs'

    nowTime = utils.format_iso_time()

    file_context = utils.fetch_context(STANZA, {'startTime': utils.format_iso_time(delta_sec=30)})

    query_params = {
        'endDateTime': nowTime,
        'startDateTime': file_context.get('startTime', nowTime),
        'orderBy': 'loggedDateTime asc',
        'top': 200
    }
    headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json;charset=utf-8'
    }
    helper.log_info("[TrendMicro Audit] request params: %s" %(str(query_params)))
    request_help = utils.request_help(2, backoff_time)

    try:
        res = request_help(
            url=endpoint + url_path,
            method="GET",
            parameters=query_params,
            headers=headers
        )
        res.raise_for_status()
        data = res.json()
        audit_logs = data["items"]
    except requests.exceptions.Timeout as e:
        helper.log_error("[TrendMicro Audit] audit log request timeout error: %s" % str(e))
        return 1
    except requests.exceptions.HTTPError as e:
        helper.log_error("[TrendMicro Audit] audit log request error: %s %s" % (str(e), str(endpoint)))
        return 1
    except Exception as e:
        helper.log_error("[TrendMicro Audit] audit log exception: %s" % str(e))
        return 1

    for audit in audit_logs:
        log_formater(helper, audit)
        audit['customerID'] = cid
        event = helper.new_event(data=json.dumps(audit), host=helper.get_arg('global_account')['username'], index=helper.get_output_index(), source=helper.get_input_type(), sourcetype=helper.get_sourcetype(), done=True, unbroken=True)
        ew.write_event(event)

    utils.update_context(STANZA, 'startTime', nowTime)
    utils.update_tpc_metrics(endpoint, headers)
