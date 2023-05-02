# encoding = utf-8

import app_common as utils

import json
import requests
import copy
import traceback
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse
import ndjson

APP_VERSION = utils.get_version()

def iso_format(helper, obj):
    try:
        if 'detectionTime' in obj:
            obj['detectionTime'] = date_parse(obj['detectionTime']).isoformat()
        if 'eventTimeDT' in obj['detail']:
            obj['detail']['eventTimeDT'] = date_parse(obj['detail']['eventTimeDT']).isoformat()
        if 'firstSeen' in obj['detail']:
            obj['detail']['firstSeen'] = date_parse(obj['detail']['firstSeen']).isoformat()
        if 'lastSeen' in obj['detail']:
            obj['detail']['lastSeen'] = date_parse(obj['detail']['lastSeen']).isoformat()
    except Exception as err:
        helper.log_error('[TrendMicro Audit] detectionTime field format error: %s'%(str(err)))

def spread_filters(detection):
    filters_list = []
    if len(detection.get('filters', [])) == 0:
        dcopy_data = copy.deepcopy(detection)
        del dcopy_data['filters']
        cim_compliant(dcopy_data)
        dcopy_data['filter'] = {}
        return [dcopy_data]
    for oat_filter in detection.get('filters', []):
        dcopy_data = copy.deepcopy(detection)
        dcopy_data.pop('filters', None)
        dcopy_data['filter'] = oat_filter
        cim_compliant(dcopy_data)
        filters_list.append(dcopy_data)
    return filters_list

def format_risk_levels(risk_level="medium"):
    query_levels = ["undefined", "info", "low", "medium", "high", "critical"]
    if risk_level not in query_levels:
        risk_level = "medium"
    return query_levels[query_levels.index(risk_level):]

def defined_risk_level(query_levels):
    risk_levels = ["undefined", "info", "low", "medium", "high", "critical"]
    for level in risk_levels:
        if level in query_levels:
            return level
    return "medium"

def cim_compliant(data):
    try:
        data["app"] = "trendmicro_v1"
        if "filter" in data:
            data["id"] = data['filter'].get('unique_id', "")
            data["description"] = data['filter'].get('description', "")
            data["severity"] = data['filter'].get('level', "undefined")
            data["mitre_technique_id"] = ",".join(data['filter'].get('techniques', []))
        else:
            data["severity"] = "undefined"
        data["dest_type"] = "endpoint"
        if "endpoint" in data:
            data["dest"] = data['endpoint'].get('guid', "")
        data["type"] = "event"
        data["user"] = data["customerID"]
    except Exception as e:
        utils.helper.log_warning(traceback.format_exc())

class OATDataPipeline:
    __uri = '/v3.0/xdr/oat/dataPipeline'

    def __init__(self,helper,endpoint,token,risk_level) -> None:
        self.__helper = helper
        self.__endpoint = endpoint
        self.__token = token
        self.__query_levels = format_risk_levels(risk_level)
        if not self.__token:
            raise Exception('no valid config')
        self.__headers = {
            'Authorization': 'Bearer ' + self.__token,
            'Content-Type': 'application/json;charset=utf-8'
        }
        self.get_setting()

    def get_setting(self):
        if not self.__token:
            raise Exception('no valid config')
        res = requests.request(
            url=self.__endpoint + self.__uri,
            method="GET",
            headers=self.__headers
        )
        if res.status_code == requests.codes.bad_request:
            config = {
                "riskLevels": self.__query_levels,
                "hasDetail": True,
            }
            res = requests.request(
                url=self.__endpoint + self.__uri,
                method="POST",
                headers=self.__headers,
                json=config
            )
            if res.status_code != requests.codes.created:
                raise Exception("[TrendMicro OAT] fail to init register")

            res = requests.request(
                url=self.__endpoint + self.__uri,
                method="GET",
                headers=self.__headers
            )
        res.raise_for_status()
        return res.json()

    def update(self, risk_level=None):
        if (not self.__endpoint) or (not self.__token):
            raise Exception('no valid config')
        if risk_level is not None:
            self.__query_levels = format_risk_levels(risk_level)
        config = {
            "riskLevels": self.__query_levels,
            "hasDetail": True,
        }
        res = requests.request(
            url=self.__endpoint + self.__uri,
            method="PATCH",
            headers=self.__headers,
            json=config
        )
        res.raise_for_status()

def validate_input(helper, definition):
    global_account = definition.parameters.get('global_account', None)
    interval = definition.parameters.get('interval', 120)
    if interval is not None:
        if int(interval) < 40:
            raise ValueError("The minimum public API access interval cannot be less than 40 seconds.")
        if int(interval) >= 60 * 60:
            raise ValueError("The maximum public API access interval must be less than 1 hour.")
    utils.update_context("GLOBAL", 'oatSettingModify', 1)

def collect_events(helper, ew):
    STANZA = helper.get_input_stanza_names()
    polling = helper.get_arg('interval')
    risk_level = helper.get_arg('risklevel')
    token = helper.get_arg('global_account')['password']
    backoff_time = int(helper.get_global_setting("backoff_time") or 10)
    endpoint = helper.get_arg('global_account')['url']
    
    if (not endpoint) or (not token):
        helper.log_info("[TrendMicro Audit] no valid config, will pass")
        return 0

    cid = utils.extractCID(token)
    query_levels = format_risk_levels(risk_level)

    parse_url = urlparse(endpoint)
    endpoint = "{}://{}".format(parse_url.scheme, parse_url.netloc)
    try:
        oat_util = OATDataPipeline(helper,endpoint,token,risk_level)
    except Exception as e:
        return 1

    global_ctx = utils.fetch_context("GLOBAL")
    if global_ctx.get('oatSettingModify', 0) == 1:
        oat_util.update(risk_level)
        utils.update_context("GLOBAL", 'oatSettingModify', 0)
    else:
        oat_setting = oat_util.get_setting()
        cloud_risk_level = defined_risk_level(oat_setting['riskLevels'])
        if cloud_risk_level != risk_level:
            utils.set_input_setting(f'vo_oat://{STANZA}', 'risk_level', cloud_risk_level)

    ft_str = "%Y-%m-%dT%H:%M:%SZ"
    nowTime = utils.format_iso_time(ft_str, 30)

    file_context = utils.fetch_context(STANZA, {'startTime': nowTime})

    query_params = {}

    headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json;charset=utf-8'
    }

    startTime = file_context.get('startTime', nowTime)
    if not startTime.endswith('Z'):
        startTime = utils.timestamp2iso(int(startTime), ft_str)
    time_group = utils.timerange_split(startTime, nowTime, 120)

    request_help = utils.request_help(2, backoff_time)
    checkpoint_time = startTime

    try:
        package_bucket = set()
        for start_time, end_time in time_group:
            curr_bucket = set()
            query_params["startDateTime"] = start_time
            query_params["endDateTime"] = end_time
            helper.log_info(start_time+" "+end_time)

            helper.log_info("[TrendMicro OAT] request to oat: %s" % str(query_params))

            res = request_help(
                url=endpoint + "/v3.0/xdr/oat/dataPipeline/packages",
                method="GET",
                parameters=query_params,
                headers=headers
            )
            res.raise_for_status()

            pk_list = res.json()['items']
            detections = []
            for package in pk_list:
                package_id = package['id']
                modified_time = package['lastModifiedDateTime']
                if package_id in package_bucket:
                    continue
                curr_bucket.add(package_id)
                res = request_help(
                    url=endpoint + "/v3.0/xdr/oat/dataPipeline/packages/" + package_id,
                    method="GET",
                    headers=headers
                )
                res.raise_for_status()
                res_body = res.json(cls=ndjson.Decoder)
                detections.extend(res_body)
            for detection in detections:
                iso_format(helper,detection)
                detection['customerID'] = cid
                for filter in spread_filters(detection):
                    if filter.get('severity', "undefined") not in query_levels:
                        continue
                    event = helper.new_event(data=json.dumps(filter), host=helper.get_arg('global_account')['username'], index=helper.get_output_index(), source=helper.get_input_type(), sourcetype=helper.get_sourcetype(), done=True, unbroken=True)
                    ew.write_event(event)
            checkpoint_time = end_time
            package_bucket = curr_bucket

    except requests.exceptions.Timeout as e:
        helper.log_error("[TrendMicro OAT] oat request timeout error: %s" % repr(e))
        if utils.isotime_delta(startTime, nowTime, ft_str) >= 60*60*24*7:
            checkpoint_time = utils.format_iso_time(ft_str)
        return 1
    except requests.exceptions.HTTPError as e:
        helper.log_error("[TrendMicro OAT] oat request error: %s %s" % (repr(e), str(endpoint)))
        if utils.isotime_delta(startTime, nowTime, ft_str) >= 60*60*24*7:
            checkpoint_time = utils.format_iso_time(ft_str)
        return 1
    except Exception as e:
        helper.log_error("[TrendMicro OAT] oat exception: %s" % repr(e))
        return 1
    finally:
        utils.update_context(STANZA, 'startTime', checkpoint_time)
    utils.update_tpc_metrics(endpoint, headers)