from io import BytesIO
import struct


class DecodeError(Exception):
    """NDEF decode error exception class."""
    pass

class Record(object):

    MAX_PAYLOAD_SIZE = 0x100000

    _known_types = dict()
    _decode_min_payload_length = 0
    _decode_max_payload_length = 0xffffffff

    @classmethod
    def register_type(cls, record_class):
        assert issubclass(record_class, Record)
        if cls != Record and id(cls._known_types) == id(Record._known_types):
            cls._known_types = {}  # shadow Record.known_types
        cls._known_types[record_class._type] = record_class


    def __init__(self, type=None, name=None, data=None):
        self.name = name
        self._data = data if data else bytearray()

    @property
    def data(self):
        if type(self) is Record:
            return self._data
        else:
            return bytes(self._encode_payload())


    def __str__(self):
        """Return an informal representation suitable for printing."""
        cls = type(self)
        if cls is Record:
            s = "NDEF Record TYPE '{r.type}'"
        else:
            name = (cls.__module__.split('.')[-1].capitalize() + cls.__name__
                    if isinstance(self, LocalRecord) else cls.__name__)
            s = "NDEF {}".format(name)
        return (s + " ID '{}' {}").format(self.name, self.data)


    @classmethod
    def _decode(cls, stream, errors, known_types):
        octet0 = stream.read(1)[0]

        MB = bool(octet0 & 0b10000000)
        ME = bool(octet0 & 0b01000000)
        CF = bool(octet0 & 0b00100000)
        SR = bool(octet0 & 0b00010000)
        IL = bool(octet0 & 0b00001000)
        TNF = octet0 & 0b00000111

        if TNF == 7:
            raise DecodeError("TNF field value must be between 0 and 6")

        try:
            struct_format = '>B' + ('B' if SR else 'L') + ('B' if IL else '')
            fields = struct.unpack(struct_format, stream.read(struct.calcsize(struct_format))) + (0,)
        except Exception as e:
            errstr = "buffer underflow at reading length fields {}".format(e)
            raise DecodeError(errstr)

        try:
            if TNF in (0, 5, 6):
                assert fields[0] == 0, "TYPE_LENGTH must be 0"
            if TNF == 0:
                assert fields[2] == 0, "ID_LENGTH must be 0"
                assert fields[1] == 0, "PAYLOAD_LENGTH must be 0"
            if TNF in (1, 2, 3, 4):
                assert fields[0] > 0, "TYPE_LENGTH must be > 0"
        except AssertionError as error:
            raise DecodeError(str(error) + " for TNF value {}", TNF)

        if fields[1] > cls.MAX_PAYLOAD_SIZE:
            errstr = "payload of more than {} octets can not be decoded"
            raise DecodeError(errstr.format(cls.MAX_PAYLOAD_SIZE))

        TYPE, ID, PAYLOAD = [stream.read(fields[i]) for i in (0, 2, 1)]

        try:
            assert fields[0] == len(TYPE), "TYPE field"
            assert fields[2] == len(ID), "ID field"
            assert fields[1] == len(PAYLOAD), "PAYLOAD field"
        except AssertionError as error:
            raise DecodeError("buffer underflow at reading {}", error)

        record_type = cls._decode_type(TNF, TYPE)
        if record_type in known_types:
            record_cls = known_types[record_type]
            min_payload_length = record_cls._decode_min_payload_length
            max_payload_length = record_cls._decode_max_payload_length
            if len(PAYLOAD) < min_payload_length:
                errstr = "payload length can not be less than {}"
                raise record_cls._decode_error(errstr, min_payload_length)
            if len(PAYLOAD) > max_payload_length:
                errstr = "payload length can not be more than {}"
                raise record_cls._decode_error(errstr, max_payload_length)
            record = record_cls._decode_payload(PAYLOAD, errors)
            assert isinstance(record, Record)
            record.name = ID
        else:
            record = Record(record_type, ID, PAYLOAD)
        return (record, MB, ME, CF)


    @classmethod
    def _decode_type(cls, TNF, TYPE):
        prefix = ('', 'urn:nfc:wkt:', '', '', 'urn:nfc:ext:',
                  'unknown', 'unchanged')
        if not 0 <= TNF <= 6:
            raise DecodeError('NDEF Record TNF values must be 0 to 6')
        if TNF in (0, 5, 6):
            TYPE = b''

        return prefix[TNF] + (TYPE.decode('ascii'))

    @classmethod
    def _decode_struct(cls, fmt, octets, offset=0, always_tuple=False):
        assert fmt[0] not in ('@', '=', '!'), "only '>' and '<' are allowed"
        assert fmt.count('*') < 2, "only one '*' expression is allowed"
        assert '*' not in fmt or fmt.find('*') > fmt.rfind('+')
        order, fmt = (fmt[0], fmt[1:]) if fmt[0] in ('>', '<') else ('>', fmt)
        try:
            values = list()
            this_fmt = fmt
            while this_fmt:
                this_fmt, plus_fmt, next_fmt = this_fmt.partition('+')
                if '*' in this_fmt:
                    this_fmt, next_fmt = this_fmt.split('*', 1)
                    if this_fmt:
                        next_fmt = '*' + next_fmt
                    elif next_fmt:
                        trailing = len(octets) - offset
                        size_fmt = struct.calcsize(next_fmt)
                        this_fmt = int(trailing / size_fmt) * next_fmt
                        next_fmt = '*' if trailing % size_fmt else ''
                    else:
                        this_fmt = str(len(octets) - offset) + 's'
                        next_fmt = ''
                struct_format = order + this_fmt
                values = values + list(struct.unpack_from(struct_format, octets, offset))
                offset = offset + struct.calcsize(struct_format)
                if plus_fmt:
                    if next_fmt.startswith('('):
                        this_fmt, next_fmt = next_fmt[1:].split(')', 1)
                        struct_format = order + values.pop() * this_fmt
                        values.append(struct.unpack_from(struct_format, octets, offset))
                        offset = offset + struct.calcsize(struct_format)
                    else:
                        struct_format = '{:d}s'.format(values.pop())
                        values.extend(struct.unpack_from(struct_format, octets, offset))
                        offset = offset + struct.calcsize(struct_format)
                this_fmt = next_fmt
        except struct_error as error:
            raise cls._decode_error(str(error))
        else:
            if len(values) == 1 and not always_tuple:
                return values[0]
            else:
                return tuple(values)


    @classmethod
    def _encode_struct(cls, fmt, *values):
        assert fmt[0] not in ('@', '=', '!'), "only '>' and '<' are allowed"
        assert fmt.count('*') < 2, "only one '*' expression is allowed"
        assert '*' not in fmt or fmt.find('*') > fmt.rfind('+')
        order, fmt = (fmt[0], fmt[1:]) if fmt[0] in ('>', '<') else ('>', fmt)
        try:
            values = list(values)
            octets = list()
            this_fmt = fmt
            while this_fmt:
                this_fmt, plus_fmt, next_fmt = this_fmt.partition('+')
                if '*' in this_fmt:
                    this_fmt, next_fmt = this_fmt.split('*', 1)
                    if this_fmt:
                        next_fmt = '*' + next_fmt
                    elif next_fmt:
                        this_fmt = len(values) * next_fmt
                        next_fmt = ''
                    else:
                        this_fmt = str(len(values[0])) + 's'
                        next_fmt = ''
                vcount = len(this_fmt) - sum(map(str.isdigit, this_fmt))
                if plus_fmt:
                    assert this_fmt, "'+' character without preceeding format"
                    if next_fmt.startswith('('):
                        length = len(values[vcount-1])
                        values.insert(vcount-1, length)
                        this_fmt += length * next_fmt[1:].split(')', 1)[0]
                        next_fmt = next_fmt[1:].split(')', 1)[1]
                        values[vcount:vcount+1] = list(values[vcount])
                        vcount = vcount + length
                    else:
                        vcount = vcount + 1
                        length = len(values[vcount-2])
                        values.insert(vcount-2, length)
                        this_fmt = this_fmt + str(length) + 's'
                struct_format = order + this_fmt
                octets.append(struct.pack(struct_format, *values[0:vcount]))
                del values[0:vcount]
                this_fmt = next_fmt
        except struct_error as error:
            raise cls._encode_error(str(error))
        else:
            return b''.join(octets)

    @classmethod
    def _value_to_ascii(cls, value, name):
        try:
            if isinstance(value, (str, bytes)):
                return (value.decode('ascii') if isinstance(value, bytes) else
                        value.encode('ascii').decode('ascii'))
            if isinstance(value, bytearray):
                return (value.decode('ascii'))
            errstr = name + ' accepts str or bytes, but not {}'
            raise TypeError(errstr, type(value).__name__)
        except UnicodeError:
            errstr = name + ' conversion requires ascii text, but got {!r}'
            raise TypeError(errstr, value)


    @classmethod
    def _value_to_unicode(cls, value, name):
        try:
            if isinstance(value, (str, bytes)):
                return (value if isinstance(value, str) else
                        value.decode('ascii'))
            if isinstance(value, bytearray):
                return value.decode('ascii')
            errstr = name + ' accepts str or bytes, but not {}'
            raise cls._type_error(errstr, type(value).__name__)
        except UnicodeError:
            errstr = name + ' conversion requires ascii text, but got {!r}'
            raise cls._value_error(errstr, value)


class GlobalRecord(Record):  # pragma: no cover
    def __init__(self, *args, **kwargs):
        assert hasattr(self, '_type'),\
            "derived class must define the '_type' class attribute"

    def _encode_payload(self):
        pass

    def _decode_payload(cls, octets, errors):
        pass

class LocalRecord(Record):  # pragma: no cover
    def __init__(self, *args, **kwargs):
        assert hasattr(self, '_type'),\
            "derived class must define the '_type' class attribute"

    def _encode_payload(self):
        pass

    def _decode_payload(cls, octets, errors):
        pass


def convert(conversion):
    def converter(setter):
        @wraps(setter)
        def wrapper(self, value):
            _convert = getattr(self, '_' + conversion)
            return setter(self, _convert(value, setter.__name__))
        return wrapper
    return
