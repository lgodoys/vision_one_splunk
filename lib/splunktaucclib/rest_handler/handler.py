#
# Copyright 2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
REST Handler.
"""


import json
import traceback
import urllib.parse
from typing import Optional, Any

from defusedxml import ElementTree
from functools import wraps

from solnlib.splunk_rest_client import SplunkRestClient
from solnlib.utils import is_true
from splunklib import binding

from .credentials import RestCredentials
from .entity import RestEntity
from .error import RestError

__all__ = ["RestHandler"]

BASIC_NAME_VALIDATORS = {
    "PROHIBITED_NAME_CHARACTERS": ["*", "\\", "[", "]", "(", ")", "?", ":"],
    "PROHIBITED_NAMES": ["default", ".", ".."],
    "MAX_LENGTH": 1024,
}

_TA_CONFIG_FILENAME = "_TA_config"
_TA_CONFIG_ENDPOINT = f"configs/conf-{_TA_CONFIG_FILENAME}"
_NEED_RELOAD_PARAMETER = "need_reload"


def _check_name_for_create(name):
    if name == "default":
        raise RestError(400, '"%s" is not allowed for entity name' % name)
    if name.startswith("_"):
        raise RestError(400, 'Name starting with "_" is not allowed for entity')


def _parse_error_msg(exc: binding.HTTPError) -> str:
    permission_msg = "do not have permission to perform this operation"
    try:
        msgs = json.loads(exc.body)["messages"]
        text = msgs[0]["text"]
    except json.JSONDecodeError:
        try:
            text = ElementTree.fromstring(exc.body).findtext("./messages/msg")
        except ElementTree.ParseError:
            return exc.body.decode()
    except (KeyError, IndexError):
        return exc.body.decode()
    if exc.status == 403 and permission_msg in text:
        return "This operation is forbidden."
    return text


def _pre_request(existing):
    """
    Encode payload before request.
    :param existing:
        if True: means must exist
        if False: means must NOT exist
    :return:
    """

    def _pre_request_wrapper(meth):
        """

        :param meth: RestHandler instance method
        :return:
        """

        def check_existing(self, name):
            if not existing:
                # for create, check name
                _check_name_for_create(name)
            # check if the entity existed
            entities = []
            try:
                entities = list(self.get(name))
            except RestError:
                pass

            if existing and not entities:
                raise RestError(
                    404,
                    '"%s" does not exist' % name,
                )
            elif not existing and entities:
                raise RestError(
                    409,
                    'Name "%s" is already in use' % name,
                )

            if entities:
                return entities[0].content
            else:
                return None

        def basic_name_validation(name: str):
            tmp_name = str(name)
            prohibited_chars = BASIC_NAME_VALIDATORS["PROHIBITED_NAME_CHARACTERS"]
            prohibited_names = BASIC_NAME_VALIDATORS["PROHIBITED_NAMES"]
            max_chars = BASIC_NAME_VALIDATORS["MAX_LENGTH"]
            val_err_msg = (
                f'{prohibited_names}, string started with "_" and string including any one '
                f'of {prohibited_chars} are reserved value which cannot be used for field Name"'
            )

            if tmp_name.startswith("_") or any(
                tmp_name == el for el in prohibited_names
            ):
                raise RestError(400, val_err_msg)

            if any(pc in prohibited_chars for pc in tmp_name):
                raise RestError(400, val_err_msg)

            if len(tmp_name) >= max_chars:
                raise RestError(
                    400, f"Field Name must be less than {max_chars} characters"
                )

        @wraps(meth)
        def wrapper(self, name, data):
            self._endpoint.validate(
                name,
                data,
                check_existing(self, name),
            )
            basic_name_validation(name)
            self._endpoint.validate_special(name, data)
            self._endpoint.encode(name, data)

            return meth(self, name, data)

        return wrapper

    return _pre_request_wrapper


def _decode_response(meth):
    """
    Decode response body.
    :param meth: RestHandler instance method
    :return:
    """

    def decode(self, name, data, acl):
        self._endpoint.decode(name, data)
        return RestEntity(
            name,
            data,
            self._endpoint.model(name),
            self._endpoint.user,
            self._endpoint.app,
            acl=acl,
        )

    @wraps(meth)
    def wrapper(self, *args, **kwargs):
        try:
            for name, data, acl in meth(self, *args, **kwargs):
                yield decode(self, name, data, acl)
        except RestError:
            raise
        except binding.HTTPError as exc:
            raise RestError(exc.status, _parse_error_msg(exc))
        except Exception:
            raise RestError(500, traceback.format_exc())

    return wrapper


class RestHandler:
    def __init__(self, splunkd_uri, session_key, endpoint, *args, **kwargs):
        self._splunkd_uri = splunkd_uri
        self._session_key = session_key
        self._endpoint = endpoint
        self._args = args
        self._kwargs = kwargs
        self._conf_name = getattr(endpoint, "conf_name", None)

        splunkd_info = urllib.parse.urlparse(self._splunkd_uri)
        self._client = SplunkRestClient(
            self._session_key,
            self._endpoint.app,
            scheme=splunkd_info.scheme,
            host=splunkd_info.hostname,
            port=splunkd_info.port,
        )
        self.rest_credentials = RestCredentials(
            self._splunkd_uri,
            self._session_key,
            self._endpoint,
        )
        self.PASSWORD = "******"

    @_decode_response
    def get(self, name, decrypt=False):
        self.reload_if_needed()
        response = self._client.get(
            self.path_segment(
                self._endpoint.internal_endpoint,
                name=name,
            ),
            output_mode="json",
        )
        return self._format_response(response, get=True, decrypt=decrypt)

    @_decode_response
    def all(self, decrypt=False, **query):
        self.reload_if_needed()
        response = self._client.get(
            self.path_segment(self._endpoint.internal_endpoint),
            output_mode="json",
            **query,
        )
        return self._format_all_response(response, decrypt)

    def get_encrypted_field_names(self, name):
        return [x.name for x in self._endpoint.model(name).fields if x.encrypted]

    @_decode_response
    @_pre_request(existing=False)
    def create(self, name, data):
        data["name"] = name
        self.rest_credentials.encrypt_for_create(name, data)
        response = self._client.post(
            self.path_segment(self._endpoint.internal_endpoint),
            output_mode="json",
            body=data,
        )
        return self._format_response(response)

    @_decode_response
    @_pre_request(existing=True)
    def update(self, name, data):
        self.rest_credentials.encrypt_for_update(name, data)
        response = self._client.post(
            self.path_segment(
                self._endpoint.internal_endpoint,
                name=name,
            ),
            output_mode="json",
            body=data,
        )
        return self._format_response(response)

    @_decode_response
    def delete(self, name):
        response = self._client.delete(
            self.path_segment(
                self._endpoint.internal_endpoint,
                name=name,
            ),
            output_mode="json",
        )
        # delete credentials if there are encrypted fields
        if self.get_encrypted_field_names(name):
            rest_credentials = RestCredentials(
                self._splunkd_uri,
                self._session_key,
                self._endpoint,
            )
            rest_credentials.delete(name)
        return self._flay_response(response)

    @_decode_response
    def disable(self, name):
        response = self._client.post(
            self.path_segment(
                self._endpoint.internal_endpoint,
                name=name,
                action="disable",
            ),
            output_mode="json",
        )
        return self._flay_response(response)

    @_decode_response
    def enable(self, name):
        response = self._client.post(
            self.path_segment(
                self._endpoint.internal_endpoint,
                name=name,
                action="enable",
            ),
            output_mode="json",
        )
        return self._flay_response(response)

    def reload_if_needed(self):
        if self._conf_name and self.is_reload_needed():
            self.reload()

    def is_reload_needed(self) -> bool:
        need_reload = self._is_reload_needed()

        if need_reload is None:
            need_reload = self._endpoint.need_reload

        return need_reload

    def _is_reload_needed(self) -> Optional[bool]:
        name = "config"
        try:
            response = self._client.get(
                self.path_segment(
                    _TA_CONFIG_ENDPOINT,
                    name=name,
                ),
                output_mode="json",
            )
        except binding.HTTPError:
            return None

        response = json.loads(response.body.read())

        if "entry" in response:
            for entry in response["entry"]:
                if entry["name"] == name and _NEED_RELOAD_PARAMETER in entry["content"]:
                    need_reload = is_true(entry["content"][_NEED_RELOAD_PARAMETER])

                    if need_reload is not None:
                        return need_reload

        return None

    def reload(self):
        self._client.get(
            self.path_segment(
                self._endpoint.internal_endpoint,
                action="_reload",
            ),
        )

    def get_endpoint(self):
        return self._endpoint

    @classmethod
    def path_segment(cls, endpoint, name=None, action=None):
        """
        Make path segment for given context in Splunk REST format:
        <endpoint>/<entity>/<action>

        :param endpoint: Splunk REST endpoint, e.g. data/inputs
        :param name: entity name for request, "/" will be quoted
        :param action: Splunk REST action, e.g. disable, enable
        :return:
        """
        template = "{endpoint}{entity}{action}"
        entity = ""
        if name:
            # all special characters except "/" will be
            # url-encoded in splunklib.binding.UrlEncoded
            entity = "/" + name.replace("/", "%2F")
        path = template.format(
            endpoint=endpoint.strip("/"),
            entity=entity,
            action="/%s" % action if action else "",
        )
        return path.strip("/")

    def _format_response(self, response, get=False, decrypt=False):
        body = response.body.read()
        try:
            cont = json.loads(body)
        except ValueError:
            raise RestError(500, "Fail to load response, invalid JSON")
        for entry in cont["entry"]:
            name = entry["name"]
            data = entry["content"]
            acl = entry["acl"]
            encrypted_field_names = self.get_encrypted_field_names(name)
            # encrypt and get clear password for get request
            if get:
                masked = self.rest_credentials.decrypt_for_get(name, data)
                if masked:
                    self._client.post(
                        self.path_segment(
                            self._endpoint.internal_endpoint,
                            name=name,
                        ),
                        body=masked,
                    )

            if not decrypt:
                # replace clear password with '******'
                for field_name in encrypted_field_names:
                    if field_name in data and data[field_name]:
                        data[field_name] = self.PASSWORD

            yield name, data, acl

    def _flay_response(self, response, decrypt=False):
        body = response.body.read()
        try:
            cont = json.loads(body)
        except ValueError:
            raise RestError(500, "Fail to load response, invalid JSON")
        for entry in cont["entry"]:
            name = entry["name"]
            data = entry["content"]
            acl = entry["acl"]
            if self._need_decrypt(name, data, decrypt):
                self._load_credentials(name, data)
            if not decrypt:
                self._clean_credentials(name, data)
            yield name, data, acl

    def _format_all_response(self, response, decrypt=False):
        body = response.body.read()
        try:
            cont = json.loads(body)
        except ValueError:
            raise RestError(500, "Fail to load response, invalid JSON")
        # cont['entry']: collection list, load credentials in one request
        if self.get_encrypted_field_names(None):
            self._encrypt_raw_credentials(cont["entry"])
        if not decrypt:
            self._clean_all_credentials(cont["entry"])

        for entry in cont["entry"]:
            name = entry["name"]
            data = entry["content"]
            acl = entry["acl"]
            yield name, data, acl

    def _load_credentials(self, name, data):
        rest_credentials = RestCredentials(
            self._splunkd_uri, self._session_key, self._endpoint
        )
        masked = rest_credentials.decrypt(name, data)
        if masked:
            # passwords.conf changed
            self._client.post(
                self.path_segment(
                    self._endpoint.internal_endpoint,
                    name=name,
                ),
                **masked,
            )

    def _encrypt_raw_credentials(self, data):
        rest_credentials = RestCredentials(
            self._splunkd_uri, self._session_key, self._endpoint
        )
        # get clear passwords for response data and get the password change list
        change_list = rest_credentials.decrypt_all(data)

        field_names = self.get_encrypted_field_names(None)
        for model in change_list:
            # only updates the defined fields in schema
            masked = dict()
            for field in field_names:
                if (
                    field in model["content"]
                    and model["content"][field] != ""
                    and model["content"][field] != self.PASSWORD
                ):
                    masked[field] = self.PASSWORD

            if masked:
                self._client.post(
                    self.path_segment(
                        self._endpoint.internal_endpoint,
                        name=model["name"],
                    ),
                    body=masked,
                )

    def _need_decrypt(self, name, data, decrypt):
        # some encrypted-needed fields are plain text in *.conf.
        encrypted_field = False
        for field in self._endpoint.model(name).fields:
            if field.encrypted is False:
                # ignore non-encrypted fields
                continue
            encrypted_field = True
            if not data.get(field.name):
                # ignore un-stored/empty fields
                continue
            if data[field.name] == RestCredentials.PASSWORD:
                # ignore already-encrypted fields
                continue
            return True

        if decrypt and encrypted_field:
            # clear credentials is required by request and
            # there are some encrypted-needed fields
            return True
        return False

    def _clean_credentials(self, name, data):
        encrypted_field_names = self.get_encrypted_field_names(name)
        for field_name in encrypted_field_names:
            if field_name in data:
                del data[field_name]

    def _clean_all_credentials(self, data):
        encrypted_field_names = self.get_encrypted_field_names(None)
        for model in data:
            for field_name in encrypted_field_names:
                if (
                    field_name in model["content"]
                    and model["content"][field_name] != ""
                ):
                    model["content"][field_name] = self.PASSWORD
