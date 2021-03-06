# -*- coding: utf-8 -*-

from .record import Record, GlobalRecord


class TextRecord(GlobalRecord):
    _type = 'urn:nfc:wkt:T'
    _decode_min_payload_length = 1

    def __init__(self, text=None, language=None, encoding=None):
        """Initialize an NDEF TextRecord. Default values are the empty text
        string, the language code 'en' for English, and UTF-8 encoding.
        """
        self.text = text if text is not None else ''
        self.language = language if language is not None else 'en'
        self.encoding = encoding if encoding is not None else 'UTF-8'

    def __str__(self):
        """Return an informal representation suitable for printing."""
        return ("NDEF TextRecord ID '{}' Text '{}'").format(self.name, self.text)

    @property
    def text(self):
        """NDEF Text Record content."""
        return self._text

    @text.setter
    def text(self, value):
        value = self._value_to_unicode(value, "text")
        self._text = value

    @property
    def language(self):
        """ISO/IANA language code for the text content."""
        return self._lang

    @language.setter
    def language(self, value):
        value = self._value_to_ascii(value, "language")
        if not (0 < len(value) < 64):
            errstr = 'language must be 1..63 characters, got {}'
            raise ValueError(errstr.format(len(value)))
        self._lang = value

    @property
    def encoding(self):
        """Text encoding when transmitted, either 'UTF-8' or 'UTF-16'."""
        return self._utfx

    @encoding.setter
    def encoding(self, value):
        if value not in ("UTF-8", "UTF-16"):
            errstr = "encoding may be 'UTF-8' or 'UTF-16', but not '{}'"
            raise ValueError(errstr.format(value))
        self._utfx = value

    def _encode_payload(self):
        """Called from Record._encode for the byte representation of the NDEF
        Text Record PAYLOAD requested through the Record.data attribute.
        """
        UTFX = self.encoding
        LANG = self.language.encode('ascii')
        TEXT = self.text.encode(UTFX)
        FLAG = self._encode_struct('B', len(LANG) | ((UTFX == "UTF-16") << 7))
        return FLAG + LANG + TEXT

    @classmethod
    def _decode_payload(cls, octets, errors):
        """Called from Record._decode with the PAYLOAD of an NDEF Text
        Record. Returns a new TextRecord instance initialized with the
        decoded data fields. Raises ndef.DecodeError if any of the
        decoding steps failed. All decoding errors are handled 'strict'.
        """
        FLAG = cls._decode_struct('B', octets)
        if FLAG & 0x3F == 0:
            raise cls._decode_error('language code length can not be zero')
        if FLAG & 0x3F >= len(octets):
            raise cls._decode_error("language code length exceeds payload")
        UTFX = "UTF-16" if FLAG >> 7 else "UTF-8"
        LANG = octets[1:1+(FLAG & 0x3F)]
        try:
            TEXT = octets[1+len(LANG):].decode(UTFX)
        except UnicodeDecodeError:
            raise cls._decode_error("can't be decoded as {}".format(UTFX))
        return cls(TEXT, LANG, UTFX)


Record.register_type(TextRecord)
