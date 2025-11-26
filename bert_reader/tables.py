'''
Table definitions
'''

import struct
import uuid


class GenericTable:
    '''
    Generic Table class
    '''
    data = {}
    filename = ''

    def binary_to_string(self, binary_data, byte_offset, length):
        '''
        Converts binary data chunk to string.
        '''
        return binary_data[byte_offset:byte_offset + length].decode('utf-8')

    def binary_to_int(self, binary_data, byte_offset, length=4):
        '''
        Converts binary data chunk to integer.
        '''
        return struct.unpack(
            'i', binary_data[byte_offset:byte_offset + length]
        )[0]

    def binary_to_byte(self, binary_data, byte_offset, length=1):
        '''
        Converts binary data chunk to byte.
        '''
        return struct.unpack(
            'B', binary_data[byte_offset:byte_offset + length]
        )[0]

    def binary_to_hex(self, binary_data, byte_offset, length):
        '''
        Converts binary data chunk to hex.
        '''
        hex_data = binary_data[byte_offset:byte_offset + length].hex()
        return ' '.join(a+b for a,b in zip(hex_data[::2], hex_data[1::2]))

    def binary_to_guid(self, binary_data, byte_offset, length):
        '''
        Converts binary data to guid.
        '''
        return uuid.UUID(
            bytes=binary_data[byte_offset:byte_offset + length]
        ).bytes_le.hex()

    def check_header_signature(self, signature):
        '''
        Checks header signature and raises an exception if its wrong
        '''
        if self.data['header_signature'] != signature:
            raise Exception(
                f'Wrong header signature: {self.data["header_signature"]}'
            )

    def read_table(self, filename):
        '''
        Reads data tabe file and returns as a binary data.
        '''
        with open(filename, "rb") as file:
            binary_data = file.read()
        return binary_data

    def print_data(self):
        '''
        Prints table data.
        '''
        print('===========')
        print(f'''{self.data['header_signature']} Table:''')
        print('===========')
        print(f'Filename: {self.filename}')
        for key, data in self.data.items():
            if key == 'hex':
                self.print_hex_data(data)
            else:
                print(key.replace('_', ' ').capitalize() + ':', data)
        print()

    def print_hex_data(self, data):
        '''
        Prints hex data fromatted in columns and rows.
        '''
        print('HEX data:')
        hexdata = [data[i:i+48] for i in range(0, len(data), 48)]
        for number, line in enumerate(hexdata):
            print(str(number * 16) + '.:\t' + line)

class GenericData(GenericTable):
    '''
    Generic Data class.
    '''
    name = ''

    def print_data(self):
        '''
        Prints data entry.
        '''
        print((len(self.name) + 1) * '-')
        print(f'{self.name}:')
        print((len(self.name) + 1) * '-')
        if self.filename != '':
            print(f'Filename: {self.filename}')
        for key, data in self.data.items():
            if key == 'hex':
                self.print_hex_data(data)
            else:
                print(key.replace('_', ' ').capitalize() + ':', data)
        print()

class Bert(GenericTable):
    '''
    Bert (Boot Error Record Table) class
    '''
    def __init__(self, filename):
        self.filename = filename
        data = self.read_table(self.filename)
        self.data = {
            'header_signature': self.binary_to_string(data, 0, 4),
            'length': self.binary_to_int(data, 4),
            'revision': self.binary_to_byte(data, 8),
            'checksum': self.binary_to_byte(data, 9),
            'oem_id': self.binary_to_string(data, 10, 6),
            'oem_revision': self.binary_to_int(data, 24),
            'creator_id': self.binary_to_string(data, 28, 4),
            'creator_revision': self.binary_to_int(data, 32),
            'boot_error_region_length': self.binary_to_int(data, 36),
            'boot_error_region': self.binary_to_hex(data, 40, 8),
            'hex': self.binary_to_hex(data, 0, 48)
        }

class Hest(GenericTable):
    '''
    Hest (Hardware Error Source Table) class
    '''
    def __init__(self, filename):
        self.filename = filename
        data = self.read_table(self.filename)
        self.data = {
            'header_signature': self.binary_to_string(data, 0, 4),
            'length': self.binary_to_int(data, 4),
            'revision': self.binary_to_byte(data, 8),
            'checksum': self.binary_to_byte(data, 9),
            'oem_id': self.binary_to_string(data, 10, 6),
            'oem_revision': self.binary_to_int(data, 24),
            'creator_id': self.binary_to_string(data, 28, 4),
            'creator_revision': self.binary_to_int(data, 32),
            'error_source_count': self.binary_to_int(data, 36),
            'error_source_structure': data[40:],
            'hex': self.binary_to_hex(data, 0, len(data))
        }

class GenericHardwareErrorSourceStructure(GenericTable):
    '''
    Generic Hardware Error Source Structure class

    Section 18.3.2.7 in ACPI Specification.
    '''
    def __init__(self, filename):
        self.filename = filename
        data = self.read_table(self.filename)
        self.data = {
            'type': self.binary_to_int(data, 0, length=2),
            'source_id': self.binary_to_int(data, 2, length=2),
            'related_source_id': self.binary_to_int(data, 4),
            'flags': self.binary_to_byte(data, 6),
            'enabled': self.binary_to_byte(data, 7),
            'number_of_records_to_preallocate': self.binary_to_int(data, 8),
            'max_sections_per_record': self.binary_to_int(data, 12),
            'max_raw_data_length': self.binary_to_int(data, 16),
            'error_status_address': self.binary_to_hex(data, 20, 12),
            'notification_structure': data[28:60],
            'error_status_block_length': self.binary_to_hex(data, 60, 4),
            'hex': self.binary_to_hex(data, 0, len(data))
        }

class GenericErrorStatusBlock(GenericData):
    '''
    Generic Error Status Block

    Section 18.3.2.7.1 in ACPI Specification.
    '''
    def __init__(self, filename):
        self.name = "Generic Error Status Block"
        self.filename = filename
        data = self.read_table(self.filename)
        self.data = {
            'block_status': data[0:4].hex(),
            'raw_data_offset': self.binary_to_hex(data, 4, 4),
            'raw_data_length': self.binary_to_int(data, 8, 4),
            'data_length': self.binary_to_int(data, 12, 4),
            'error_severity': self.get_severity(data, 16, 4),
        }
        self.generic_error_data_entry = GenericErrorDataEntry(data[20:])
        # self.data['hex'] = self.binary_to_hex(data, 0, len(data))

    def print_data(self):
        super().print_data()
        self.generic_error_data_entry.print_data()

    def get_severity(self, data, start, length=4):
        '''
        Get error severity from data.
        '''
        severity = self.binary_to_int(data, start, length)
        severity_text = [
            'Recoverable',
            'Fatal',
            'Correctable',
            'None']
        if severity < len(severity_text):
            return f'{severity_text[severity]}({severity})'
        return f'unknown({severity})'

class GenericErrorDataEntry(GenericData):
    '''
    Generic Error Data Entry class

    Section 18.3.2.7.1 in ACPI Specification.
    '''
    def __init__(self, data):
        self.name = "Generic Error Data Entry"
        section_type_guid = self.binary_to_guid(data, 0, 16)
        section = section_types.get(
            section_type_guid,
            {
                'name': 'Unknown',
                'class': None
            }
        )
        self.data = {
            "section_type": f'''{section['name']} ({section_type_guid})''',
            "error_severity": self.binary_to_int(data, 16),
            "revision": data[20:22].hex(),
            "validation_bits": data[22:23].hex(),
            "flags": data[23:24].hex(),
            "error_data_length": self.binary_to_int(data, 24),
            "fru_id": data[28:44].hex(),
            "fru_text": self.binary_to_string(data, 44, 20),
            "timestamp": data[64:72].hex(),
        }
        if section['class']:
            self.error_record = section['class'](data[72:])
        else:
            self.error_record = None
        self.data['hex'] = self.binary_to_hex(data, 0, len(data))

    def print_data(self):
        super().print_data()
        if self.error_record:
            self.error_record.print_data()

class CommonPlatformErrorRecord(GenericData):
    '''
    Common Platform Error Record class.

    Appendix N in UEFI Specification.
    '''

class FirmwareErrorRecordReference(CommonPlatformErrorRecord):
    '''
    Firmware Error Record Reference  class.

    Appendix N.2.10 in UEFI Specification
    '''
    def __init__(self, data):
        self.name = 'Firmware Error Record Reference'
        self.data = {
            'firmware_error_record_type': self.binary_to_byte(data, 0, 1),
            'revision': self.binary_to_byte(data, 1, 1),
            'reserved': self.binary_to_hex(data, 2, 6),
            'record_identifier': self.binary_to_hex(data, 8, 8),
            'record_identifier_GUID_extension': self.binary_to_guid(
                data, 16, 16
            ),
            'hex': self.binary_to_hex(data, 32, len(data) - 32)
        }

section_types = {
    "9876ccad47b44bdbb65e16f193c4f3db": {
        "name": "Processor Generic",
        "error_record_reference": {}
    },
    "dc3ea0b0a1444797b95b53fa242b6e1d": {
        "name": "Processor Specific - IA32/X64",
        "error_record_reference": {}
    },
    "e429faf13cb711d4bca70080c73c8881": {
        "name": "Processor Specific - IPF",
        "error_record_reference": {}
    },
    "e19e3d16bc1111e49caac2051d5d46b0": {
        "name": "Processor Specific - ARM",
        "error_record_reference": {}
    },
    "a5bc11146f644edeb8633e83ed7c83b1": {
        "name": "Platform Memory",
        "error_record_reference": {}
    },
    "d995e954bbc1430fad91b44dcb3c6f35": {
        "name": "PCIe",
        "error_record_reference": {}
    },
    "81212a9609ed499694718d729c8e69ed": {
        "name": "Firmware Error Record Reference",
        'class': FirmwareErrorRecordReference,
        "error_record_reference": {}
    },
    "c57539633b844095bf78eddad3f9c9dd": {
        "name": "PCI/PCI-X Bus",
        "error_record_reference": {}
    },
    "eb5e4685ca664769b6a226068b001326": {
        "name": "DMAr Generic",
        "error_record_reference": {}
    },
    "71761d3732b245cda7d0b0fedd93e8cf": {
        "name": "Intel® VT for Directed I/O specific DMAr section",
        "error_record_reference": {}
    },
    "036f84e17f37428ca79e575fdfaa84ec": {
        "name": "IOMMU specific DMAr section",
        "error_record_reference": {}
    }
}
