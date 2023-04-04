

# encoding = utf-8
import app_common as utils

import requests
from urllib.parse import urlparse
from datetime import datetime
from dateutil.parser import parse as date_parse
import json
import sys

APP_VERSION = utils.get_version()

def mapInvestigationStatus(status):
    if not isinstance(status, int):
        return status
    status_map = {
        0: "New",
        1: "In progress",
        2: "Resolved: True Positive",
        3: "Resolved: False Positive"
        }
    if status in status_map:
        return status_map[status]
    else:
        return 'Unknown'
    
def iso_format(helper, obj):
    try:
        if 'updatedDateTime' in obj:
            obj['updatedDateTime'] = date_parse(obj['updatedDateTime']).isoformat()
        if 'createdDateTime' in obj:
            obj['createdDateTime'] = date_parse(obj['createdDateTime']).isoformat()
    except Exception as err:
        helper.log_error('[TrendMicro Audit] loggedDateTime field format error: %s'%(str(err)))

def cim_compliant(alert):
    try:
        detail = alert.get('detail',{})
        if "app" not in alert:
            alert['app'] = 'trendmicro_v1'
        if 'description' not in alert:
            alert['description'] = alert['workbenchName']
        if 'signature' not in alert:
            alert['signature'] = detail.get('description')
        if 'id' not in alert:
            alert['id'] = alert['workbenchID']
        if 'type' not in alert:
            alert['type'] = 'alert'
        if 'user' not in alert:
            alert['user'] = alert['customerID']
        if 'dest' not in alert:
            entity_ids = []
            for impact in detail.get('impactScope',[]):
                for entity in impact.get('entities',[]):
                    entity_ids.append(entity['entityId'])
            alert['dest'] = ','.join(entity_ids)
    except Exception as e:
        utils.helper.log_error(e)
        #utils.helper.log_warning(traceback.format_exc())

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    global_account = definition.parameters.get('global_account', None)
    interval = definition.parameters.get('interval',None)
    if interval is not None and int(interval) < 10:
        raise ValueError('The minimum public API access interval cannot be less than 10 seconds.')
    pass

def collect_events(helper, ew):
    STANZA = helper.get_input_stanza_names()
    token = helper.get_arg('global_account')['password']
    endpoint = helper.get_global_setting("endpoint")
    if (not endpoint) or (not token):
        helper.log_info("[TrendMicro Audit] no valid config, will pass")
        return 0
    
    parse_url = urlparse(endpoint)
    endpoint = '{}://{}'.format(parse_url.scheme, parse_url.netloc)
    
    backoff_time = float(helper.get_global_setting('backoff_time') or 10)

    cid = utils.extractCID(token)
    
    try:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer {}'.format(token)
        }

        nowTime = utils.format_iso_time()
        
        params = {}
        
        params['endDateTime'] = nowTime
        
        file_context = utils.fetch_context(STANZA,{'startDateTime': nowTime})
        
        params['startDateTime'] = file_context.get('startDateTime',nowTime)
        params['orderBy'] = 'updatedDateTime desc'
        
        request_help = utils.request_help(2, backoff_time)
        url_path = '/v3.0/workbench/alerts'
        
        try:
            res = request_help(url=endpoint+url_path, method='GET', parameters=params, headers=headers)
            res.raise_for_status()
            json_obj = res.json()
            if 'error' in json_obj:
                helper.log_error('Error desde el workbench: %s'%(str(json_obj['error'])))
            info = json_obj['items']
            for alert in info:
                large_attr_list = ['highlightedObjects','affectedEntities']
                for attr in large_attr_list:
                    if attr in alert:
                        del alert[attr]
                alert['customerID'] = cid
                invest_status = alert['investigationStatus']
                alert['investigationStatus'] = mapInvestigationStatus(invest_status)
                iso_format(helper,alert)
                cim_compliant(alert)
                event_data = json.dumps(alert)
                if sys.getsizeof(event_data) > 999999:
                    del alert['detail']
                    event_data = json.dumps(alert)
                event = helper.new_event(data=event_data, host=helper.get_arg('global_account')['username'], index=helper.get_output_index(), source=helper.get_input_type(), sourcetype=helper.get_sourcetype(), done=True, unbroken=True)
                ew.write_event(event)
        except requests.exceptions.HTTPError as e:
            helper.log_error('[TrendMicro XDR] workbench request error: %s %s'%(str(e), str(endpoint)))
            return 1
        except requests.exceptions.Timeout as e:
            helper.log_error('[TrendMicro XDR] workbench request timeout error: %s'%(str(e)))
            return 1
        except Exception as e:
            helper.log_error('[TrendMicro XDR] workbench exception: %s'%(str(e)))
            
        utils.update_context(STANZA,'startDateTime',nowTime)
        utils.update_tpc_metrics(endpoint,headers)
            
    
    except RuntimeError as e:
        helper.log_error('[TrendMicro XDR] workbench unknown error: %s'%(str(e)))
        return 1
