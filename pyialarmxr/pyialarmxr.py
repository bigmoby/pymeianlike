import logging

import re
import socket

from collections import OrderedDict
from typing import Union

from lxml import etree
import xmltodict
import uuid
import time

log = logging.getLogger(__name__)

RECV_BUF_SIZE = 1024

def _to_str_item(text):
    text = str(text)
    return 'STR,%d|%s' % (len(text), text)


def _to_pwd_item(text):
    return 'PWD,%d|%s' % (len(text), text)


class IAlarmXRGenericException(Exception):
    """Generic iAlarmXR Exception"""

    def __init__(self, *args):
        if args:
            self.message = args[0]
        else:
            self.message = None

    def __str__(self):
        if self.message:
            return 'IAlarmXRGenericException, {0} '.format(self.message)
        else:
            return 'IAlarmXRGenericException has been raised'

class IAlarmXRSocketTimeoutException(Exception):
    """Socket Timeout iAlarmXR Exception"""

    def __init__(self, *args):
        if args:
            self.message = args[0]
        else:
            self.message = None

    def __str__(self):
        if self.message:
            return 'IAlarmXRSocketTimeoutException, {0} '.format(self.message)
        else:
            return 'IAlarmXRSocketTimeoutException has been raised'            


class IAlarmXR(object):
    """
    Interface the iAlarmXR security systems.
    """

    ARMED_AWAY = 0
    DISARMED = 1
    ARMED_STAY = 2
    CANCEL = 3
    TRIGGERED = 4

    ZONE_NOT_USED = 0
    ZONE_IN_USE = (1 << 0)
    ZONE_ALARM = (1 << 1)
    ZONE_BYPASS = (1 << 2)
    ZONE_FAULT = (1 << 3)
    ZONE_LOW_BATTERY = (1 << 4)
    ZONE_LOSS = (1 << 5)

    IALARM_P2P_DEFAULT_PORT = 18034
    IALARM_P2P_DEFAULT_HOST = "47.91.74.102"

    def __init__(self, uid: str, password: str, host: str = IALARM_P2P_DEFAULT_HOST, port: int = IALARM_P2P_DEFAULT_PORT) -> None:
        """
        :param host: host of the iAlarm security system (e.g. its IP address)
        :param port: port of the iAlarm security system (should be '18034')
        :param uid: username of the iAlarm security system
        :param password: password of the iAlarm security system
        """

        self.host = host
        self.port = port
        self.uid = uid
        self.password = password
        self.uuid_reference = uuid.uuid4()
        self.seq = 0
        self.sock = None

    def ensure_connection_is_open(self) -> None:
        if self.sock is None or self.sock.fileno() == -1:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10.0)
        else:
            return

        self.seq = 0
        try:
            self.sock.connect((self.host, self.port))
        except socket.timeout as timeout_err:            
            self._close_connection()
            raise IAlarmXRSocketTimeoutException('IAlarmXR P2P service socket timeout thrown: {}'.format(timeout_err)) from timeout_err            
        except (OSError, ConnectionRefusedError) as err:
            self._close_connection()
            raise ConnectionError('Connection to the alarm system failed: {}'.format(err)) from err            

        cmd = OrderedDict()
        cmd['Id'] = _to_str_item(self.uid)
        cmd['Pwd'] = _to_pwd_item(self.password)
        cmd['Type'] = 'TYP,ANDROID|0'
        cmd['Token'] = _to_str_item(str(self.uuid_reference))
        cmd['Action'] = 'TYP,IN|0'
        cmd['PemNum'] = 'STR,5|26'
        cmd['DevVersion'] = None
        cmd['DevType'] = None
        cmd['Err'] = None

        xpath: str = '/Root/Pair/Client'
        root_dict: dict = self._create_root_dict(xpath, cmd)

        xml_pair_message: str = etree.tostring(self._convert_dict_to_xml(root_dict), pretty_print=False)

        # print(f"==========>>> Pair message request [ {xml_pair_message}} ]")

        self.seq += 1
        msg = b'@ieM%04d%04d0000%s%04d' % (len(xml_pair_message), self.seq, self._xor(xml_pair_message), self.seq)
        
        self.sock.send(msg)

        # consume response message, it's mandatory to protocol to skip the Pair Client response message
        self._receive()

        self.ensure_pair_connection()

    def ensure_pair_connection(self) -> None:
        cmd = OrderedDict()
        cmd['Addr'] = None
        cmd['Flag'] = None
        cmd['Err'] = None

        xpath = '/Root/Pair/P2p'
        root_dict: dict = self._create_root_dict(xpath, cmd)

        xml_pair_command: str = etree.tostring(self._convert_dict_to_xml(root_dict), pretty_print=False)

        self.seq += 1
        msg = b'@ieM%04d%04d0000%s%04d' % (len(xml_pair_command), self.seq, self._xor(xml_pair_command), self.seq)
        self.sock.send(msg)

        # consume response message, it's mandatory to protocol to skip the Pair P2P response message
        self._receive()

        self.ipc_list()

    def ipc_list(self) -> None:
        cmd = OrderedDict()
        cmd['Total'] = None
        cmd['Offset'] = "S32,0,0|0"
        cmd['Ln'] = None
        cmd['Err'] = None

        xpath: str = '/Root/Host/IpcList'
        root_dict: dict = self._create_root_dict(xpath, cmd)

        xml_ipc_list_command: str = etree.tostring(self._convert_dict_to_xml(root_dict), pretty_print=False)

        self.seq += 1
        msg = b'@ieM%04d%04d0000%s%04d' % (
            len(xml_ipc_list_command), self.seq, self._xor(xml_ipc_list_command), self.seq)
        self.sock.send(msg)

        # consume response message, it's mandatory to protocol to skip the Host IpcList response message
        self._receive()

        self.get_version()

    def get_version(self) -> None:
        cmd = OrderedDict()
        cmd['DevType'] = None
        cmd['Dev'] = None
        cmd['Ver'] = None
        cmd['CodeType'] = None
        cmd['Err'] = None

        xpath: str = '/Root/Host/GetVersion'
        root_dict: dict = self._create_root_dict(xpath, cmd)

        xml_get_version_command: str = etree.tostring(self._convert_dict_to_xml(root_dict), pretty_print=False)

        self.seq += 1
        msg = b'@ieM%04d%04d0000%s%04d' % (
            len(xml_get_version_command), self.seq, self._xor(xml_get_version_command), self.seq)
        self.sock.send(msg)

        # consume response message
        self._receive()

    def pair(self) -> None:
        command: OrderedDict[str, Union[str, None]] = OrderedDict()
        command['Id'] = _to_str_item(self.uid)
        command['Err'] = None

        self._send_request('/Root/Pair/Push', command)

    def _uuid_regenerate(self) -> None:
        """Return last valid UUID"""
        self.uuid_reference = uuid.uuid4()

    def _close_connection(self) -> None:
        if self.sock and self.sock.fileno() != 1:
            self.sock.close()

    def _send_request_list(self, xpath: str, command: dict, offset: int = 0, partial_list: list = None):
        if partial_list is None:
            partial_list = []
        if offset > 0:
            command['Offset'] = 'S32,0,0|%d' % offset
        root_dict: dict = self._create_root_dict(xpath, command)
        self._send_dict(root_dict)
        response: dict = self._receive(True)

        if partial_list is None:
            partial_list = []

        total: int = self._clean_response_dict(response, '%s/Total' % xpath)
        ln: int = self._clean_response_dict(response, '%s/Ln' % xpath)

        for counter in list(range(ln)):
            partial_list.append(
                self._clean_response_dict(response, '%s/L%d' % (xpath, counter)))
        offset += ln

        if total > offset:
            # Continue getting elements increasing the offset
            self._send_request_list(xpath, command, offset, partial_list)

        return partial_list

    def _send_request(self, xpath: str, command: OrderedDict[str, Union[str, None]]) -> dict:
        root_dict: dict = self._create_root_dict(xpath, command)

        self._send_dict(root_dict)
        response = self._receive(True)
        
        return self._clean_response_dict(response, xpath)

    def get_mac(self) -> str:
        mac = ""
        command: OrderedDict[str, None] = OrderedDict()
        command['Mac'] = None
        command['Name'] = None
        command['Ip'] = None
        command['Gate'] = None
        command['Subnet'] = None
        command['Dns1'] = None
        command['Dns2'] = None
        command['Err'] = None

        self.ensure_connection_is_open()
        network_info = self._send_request('/Root/Host/GetNet', command)
        self._close_connection()
        
        if network_info is not None:
            mac = network_info.get("Mac", "")

        if mac:
            return mac
        else:
            raise ConnectionError('An error occurred trying to connect to the alarm '
                                  'system or received an unexpected reply')

    def get_status(self) -> int:
        command: OrderedDict[str, Union[str, None]] = OrderedDict()
        command['DevStatus'] = None
        command['Err'] = None

        self.ensure_connection_is_open()
        alarm_status: dict = self._send_request('/Root/Host/GetAlarmStatus', command)

        if alarm_status is None:
            raise ConnectionError('An error occurred trying to connect to the alarm '
                                  'system')

        status = int(alarm_status.get("DevStatus", -1))
        if status == -1:
            raise ConnectionError('Received an unexpected reply from the alarm')

        zone_alarm = False

        command: dict = OrderedDict()
        command['Total'] = None
        command['Offset'] = 'S32,0,0|0'
        command['Ln'] = None
        command['Err'] = None

        zone_status: list[int] = self._send_request_list('/Root/Host/GetByWay', command)
        self._close_connection()

        if zone_status is None:
            raise ConnectionError('An error occurred trying to connect to the alarm '
                                  'system')

        for zone in zone_status:
            if zone & self.ZONE_ALARM:
                zone_alarm = True

        if (status == self.ARMED_AWAY or status == self.ARMED_STAY) and zone_alarm:
            return self.TRIGGERED

        return status

    def arm_away(self) -> None:
        command: OrderedDict[str, Union[str, None]] = OrderedDict()
        command['DevStatus'] = 'TYP,ARM|0'
        command['Err'] = None
        self.ensure_connection_is_open()
        self._send_request('/Root/Host/SetAlarmStatus', command)
        self._close_connection()

    def arm_stay(self) -> None:
        command: OrderedDict[str, Union[str, None]] = OrderedDict()
        command['DevStatus'] = 'TYP,STAY|2'
        command['Err'] = None
        self.ensure_connection_is_open()
        self._send_request('/Root/Host/SetAlarmStatus', command)
        self._close_connection()

    def disarm(self) -> None:
        command: OrderedDict[str, Union[str, None]] = OrderedDict()
        command['DevStatus'] = 'TYP,DISARM|1'
        command['Err'] = None
        self.ensure_connection_is_open()
        self._send_request('/Root/Host/SetAlarmStatus', command)
        self._close_connection()

    def cancel_alarm(self) -> None:
        command: OrderedDict[str, Union[str, None]] = OrderedDict()
        command['DevStatus'] = 'TYP,CLEAR|3'
        command['Err'] = None
        self.ensure_connection_is_open()
        self._send_request('/Root/Host/SetAlarmStatus', command)
        self._close_connection()

    def _send_dict(self, root_dict) -> None:
        
        xml_command_request: str = etree.tostring(self._convert_dict_to_xml(root_dict), pretty_print=False)

        # print(f"==========>>> Request message [ {xml_command_request} ]")

        self.seq += 1
        msg = b'@ieM%04d%04d0000%s%04d' % (len(xml_command_request), self.seq, self._xor(xml_command_request), self.seq)
        self.sock.send(msg)

    def _select(self, mydict: OrderedDict, path: str):
        elem = mydict
        try:
            for i in path.strip('/').split('/'):
                try:
                    i = int(i)
                    elem = elem[i]
                except ValueError:
                    elem = elem.get(i)
        except:
            pass
        return elem

    def _receive(self, validate_error_msg : bool = False) -> Union[str, dict, OrderedDict]:
        data: bytes = None
        try:
            self.sock.settimeout(10.0)
            data = self.sock.recv(RECV_BUF_SIZE)
        except socket.timeout as timeout_err:
            self._close_connection()
            raise IAlarmXRSocketTimeoutException('IAlarmXR P2P service socket timeout thrown: {}'.format(timeout_err)) from timeout_err   
        except (OSError, ConnectionRefusedError) as err:
            self._close_connection()
            raise ConnectionError('Connection error: {}'.format(err)) from err

        if not data:
            self._close_connection()
            raise ConnectionError("Connection error, received no reply")

        if (type(data) == str):
            data = data.encode()
        
        head = data[0:4]

        if head == b'@ieM':
            xpath = '/Root/Pair/Client'
            response_message: OrderedDict = xmltodict.parse(self._xor(data[16:-4]).decode(), xml_attribs=False, dict_constructor=dict, postprocessor=self._xml_read)
            
            self.push = self._select(response_message, xpath)
            err = self._select(response_message, '%s/Err' % xpath)
            
            if err is not None and err != 0:
                self._close_connection()
                # print(f"==========>>> Response error message [ {response_message} ]")
                self._uuid_regenerate()
                raise IAlarmXRGenericException("Pair subscription error")

            # print(f"==========>>> Response message [ {response_message} ]")
            return response_message
        
        else:
            self._close_connection()
            raise IAlarmXRGenericException("Response error")


    @staticmethod
    def _xml_read(_path, key, value):
        if value is None or not isinstance(value, str):
            return key, value

        err_re = re.compile(r'ERR\|(\d{2})')
        mac_re = re.compile(r'MAC,(\d+)\|(([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))')
        s32_re = re.compile(r'S32,(\d+),(\d+)\|(\d*)')
        str_re = re.compile(r'STR,(\d+)\|(.*)')
        typ_re = re.compile(r'TYP,(\w+)\|(\d+)')

        if err_re.match(value):
            value = int(err_re.search(value).groups()[0])
        elif mac_re.match(value):
            value = str(mac_re.search(value).groups()[1])
        elif s32_re.match(value):
            value = int(s32_re.search(value).groups()[2])
        elif str_re.match(value):
            value = str(str_re.search(value).groups()[1])
        elif typ_re.match(value):
            value = int(typ_re.search(value).groups()[1])
        # Else: we are not interested in this value, just keep it as is

        return key, value

    @staticmethod
    def _convert_dict_to_xml_recurse(parent: etree.Element, dictitem: dict) -> None:
        assert not isinstance(dictitem, type([]))

        if isinstance(dictitem, dict):
            for (tag, child) in dictitem.items():
                if isinstance(child, type([])):
                    # iterate through the array and convert
                    for list_child in child:
                        elem: etree.Element = etree.Element(tag)
                        parent.append(elem)
                        IAlarmXR._convert_dict_to_xml_recurse(elem, list_child)
                else:
                    elem = etree.Element(tag)
                    parent.append(elem)
                    IAlarmXR._convert_dict_to_xml_recurse(elem, child)
        else:
            if dictitem is not None:
                # None Element should be written without "None" value
                parent.text = str(dictitem)

    @staticmethod
    def _convert_dict_to_xml(xmldict: dict):
        # Converts a dictionary to an XML ElementTree Element
        root_tag = list(xmldict.keys())[0]
        root: etree.Element = etree.Element(root_tag)
        IAlarmXR._convert_dict_to_xml_recurse(root, xmldict[root_tag])
        return root

    @staticmethod
    def _create_root_dict(path, my_dict=None) -> dict:
        if my_dict is None:
            my_dict = {}
        root = {}
        elem = root
        plist = path.strip('/').split('/')
        k = len(plist) - 1
        for i, j in enumerate(plist):
            elem[j] = {}
            if i == k:
                elem[j] = my_dict
            elem = elem.get(j)
        return root

    @staticmethod
    def _clean_response_dict(response: dict, path: str) -> Union[int, dict]:
        for item_i in path.strip('/').split('/'):
            try:
                item_i = int(item_i)
                response = response[item_i]
            except ValueError:
                response = response.get(item_i)
        return response

    @staticmethod
    def _xor(xml: str) -> bytearray:
        sz = bytearray.fromhex(
            '0c384e4e62382d620e384e4e44382d300f382b382b0c5a6234384e304e4c372b10535a0c20432d171142444e58422c421157322a204036172056446262382b5f0c384e4e62382d620e385858082e232c0f382b382b0c5a62343830304e2e362b10545a0c3e432e1711384e625824371c1157324220402c17204c444e624c2e12')
        buf: bytearray = bytearray(xml)

        for tmp_i in range(len(xml)):
            ki = tmp_i & 0x7f
            buf[tmp_i] = buf[tmp_i] ^ sz[ki]
        return buf