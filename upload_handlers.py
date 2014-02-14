
import base64
from django.core.files.uploadhandler import FileUploadHandler, StopUpload
from django.utils.datastructures import MultiValueDict
from django.http.multipartparser import (
    LazyStream, ChunkIter, MultiPartParserError, Parser, FIELD, FILE, exhaust)
from django.utils.encoding import force_text
from django.utils.text import unescape_entities
from django.core.files.uploadhandler import SkipFile

import app_settings as settings
from .storage import EncryptedUploadedFile


# From http://stackoverflow.com/questions/15374190/
# accessing-other-form-fields-in-a-custom-django-upload-handler
# Thanks to @TKKocheran
class IntelligentUploadHandler(FileUploadHandler):
    """
    An upload handler which overrides the default multipart parser to allow
    simultaneous parsing of fields and files... intelligently. Subclass this
    for real and true awesomeness.
    """

    def __init__(self, *args, **kwargs):
        super(IntelligentUploadHandler, self).__init__(*args, **kwargs)

    def field_parsed(self, field_name, field_value):
        """
        A callback method triggered when a non-file field has been parsed
        successfully by the parser. Use this to listen for new fields being
        parsed.
        """
        pass

    def handle_raw_input(
            self, input_data, META, content_length, boundary, encoding=None):
        """
        Parse the raw input from the HTTP request and split items into fields
        and files, executing callback methods as necessary.

        Shamelessly adapted and borrowed from
        django.http.multiparser.MultiPartParser.
        """
        # following suit from the source class, this is imported here to avoid
        # a potential circular import
        from django.http import QueryDict

        # create return values
        self.POST = QueryDict('', mutable=True)
        self.FILES = MultiValueDict()

        # initialize the parser and stream
        stream = LazyStream(ChunkIter(input_data, self.chunk_size))
        # whether or not to signal a file-completion at the beginning
        # of the loop.
        old_field_name = None
        counter = 0

        try:
            for item_type, meta_data, field_stream in Parser(stream, boundary):
                if old_field_name:
                    # we run this test at the beginning of the next loop since
                    # we cannot be sure a file is complete until we hit the
                    # next boundary/part of the multipart content.
                    file_obj = self.file_complete(counter)

                    if file_obj:
                        # if we return a file object, add it to the files dict
                        self.FILES.appendlist(force_text(
                            old_field_name, encoding,
                            errors='replace'), file_obj)

                    # wipe it out to prevent havoc
                    old_field_name = None
                try:
                    disposition = meta_data['content-disposition'][1]
                    field_name = disposition['name'].strip()
                except (KeyError, IndexError, AttributeError):
                    continue

                transfer_encoding = meta_data.get('content-transfer-encoding')

                if transfer_encoding is not None:
                    transfer_encoding = transfer_encoding[0].strip()

                field_name = force_text(field_name, encoding, errors='replace')

                if item_type == FIELD:
                    # this is a POST field
                    if transfer_encoding == "base64":
                        raw_data = field_stream.read()
                        try:
                            data = str(raw_data).decode('base64')
                        except:
                            data = raw_data
                    else:
                        data = field_stream.read()

                    self.POST.appendlist(field_name, force_text(
                        data, encoding, errors='replace'))

                    # trigger listener
                    self.field_parsed(field_name, self.POST.get(field_name))
                elif item_type == FILE:
                    # this is a file
                    file_name = disposition.get('filename')

                    if not file_name:
                        continue

                    # transform the file name
                    file_name = force_text(
                        file_name, encoding, errors='replace')
                    file_name = self.IE_sanitize(unescape_entities(file_name))

                    content_type = meta_data.get(
                        'content-type', ('',))[0].strip()

                    try:
                        charset = meta_data.get('content-type', (0, {}))[1]\
                            .get('charset', None)
                    except:
                        charset = None

                    try:
                        file_content_length = int(
                            meta_data.get('content-length')[0])
                    except (IndexError, TypeError, ValueError):
                        file_content_length = None

                    counter = 0

                    # now, do the important file stuff
                    try:
                        # alert on the new file
                        kwargs = {
                            'content_type': content_type,
                            'content_length': file_content_length,
                            'charset': charset}
                        self.new_file(field_name, file_name, **kwargs)

                        # chubber-chunk it
                        for chunk in field_stream:
                            # we need AES compatibles blocks (multiples of 16 bits)
                            over_bytes = len(chunk) % 16
                            if over_bytes:
                                over_chunk =\
                                    field_stream.read(16 - over_bytes)
                                chunk += over_chunk

                            if transfer_encoding == "base64":
                                try:
                                    chunk = base64.b64decode(chunk)
                                except Exception as e:
                                    # since this is anly a chunk, any
                                    # error is an unfixable error
                                    raise MultiPartParserError(
                                        "Could not decode base64 data: %r" % e)

                            chunk_length = len(chunk)
                            self.receive_data_chunk(chunk, counter)
                            counter += chunk_length

                            if counter > settings.UPLOAD_FILE_SIZE_LIMIT:
                                raise SkipFile('File is too big.')
                            # ... and we're done
                    except SkipFile:
                        # just eat the rest
                        exhaust(field_stream)
                    else:
                        # handle file upload completions on next iteration
                        old_field_name = field_name

        except StopUpload as e:
            # if we get a request to stop the upload,
            # exhaust it if no con reset
            if not e.connection_reset:
                exhaust(input_data)
        else:
            # make sure that the request data is all fed
            exhaust(input_data)

        # signal the upload has been completed
        self.upload_complete()

        return self.POST, self.FILES

    def IE_sanitize(self, filename):
        """Cleanup filename from Internet Explorer full paths."""
        return filename and filename[filename.rfind("\\") + 1:].strip()


class SecureFileUploadHandler(IntelligentUploadHandler):
    ''' this file uploader ensures the file will be written directly encrypted on disk, 
    by-passing the plain temp file creation. '''

    def __init__(self, *args, **kwargs):
        super(SecureFileUploadHandler, self).__init__(*args, **kwargs)
        self.passphrase = None
        self.expire_date = None
        self.one_time = False

    def handle_raw_input(
            self, input_data, META, content_length, boundary, encoding=None):

        self.content_length = content_length
        if content_length > settings.UPLOAD_FILE_SIZE_LIMIT:
            raise SkipFile

        return super(SecureFileUploadHandler, self).handle_raw_input(
            input_data, META, content_length, boundary, encoding)

    def field_parsed(self, field_name, field_value):

        if field_name == 'passphrase':
            self.passphrase = field_value
        if field_name == 'expire_date':
            self.expire_date = field_value
            try:
                self.one_time = int(self.expire_date) == 0
            except ValueError:
                pass
            
    def receive_data_chunk(self, raw_data, start):
        self.file.encrypt_and_write(raw_data)

    def new_file(self, field_name, file_name, *args, **kwargs):

        super(SecureFileUploadHandler, self).new_file(
            field_name, file_name, *args, **kwargs)

        if self.passphrase:
            kwargs['clear_filename'] = file_name
            for attr in ('passphrase', 'expire_date', 'one_time'):
                kwargs[attr] = getattr(self, attr, None)
            self.file = EncryptedUploadedFile(*args, **kwargs)
        else:
            raise SkipFile('No passphrase')

    def file_complete(self, file_size):

        self.file.seek(0)
        from .models import EncryptedUploadedFileMetaData
        EncryptedUploadedFileMetaData.update(self.file, size=file_size)
        self.file.size = file_size
        return self.file

    def upload_complete(self):
        pass

