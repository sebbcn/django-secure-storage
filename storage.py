
from uuid import uuid4
from django.utils.timezone import now
from datetime import timedelta
from os.path import join
from django.core.files.storage import FileSystemStorage
from django.core.files.uploadedfile import UploadedFile

from .encryption import get_cipher_and_iv, padding
import app_settings as settings
from .models import EncryptedUploadedFileMetaData


class ExpiredFile(Exception):
    pass


class InexistentFile(Exception):
    pass


class EncryptedUploadedFile(UploadedFile):

    def __init__(self, *args, **kwargs):

        self.passphrase = kwargs.pop('passphrase')
        self.mode = kwargs.pop('mode')
        self.name = kwargs.get('name')
        if self.name:
            # existing file
            self.file = self.open_file()
            super(EncryptedUploadedFile, self).__init__(
                self.file, **kwargs)
            EncryptedUploadedFileMetaData.load(self)
            self.cipher = get_cipher_and_iv(self.passphrase, self.iv)[0]

        else:
            # new file
            self.cipher, self.iv = get_cipher_and_iv(self.passphrase)
            self.name = EncryptedFileSystemStorage().get_available_name()
            self.file = self.open_file()
            expire = kwargs.pop('expire_date')
            if expire is None:
                self.expire_date = now() + timedelta(days=10 * 365)
            elif int(expire) > 0:
                self.expire_date = now() + timedelta(seconds=int(expire))

            self.clear_filename = kwargs.pop('clear_filename')
            self.one_time = kwargs.pop('one_time')
            kwargs['size'] = kwargs.pop('content_length')
            
            super(EncryptedUploadedFile, self).__init__(
                self.file, self.name, **kwargs)
            EncryptedUploadedFileMetaData.save_(self)

    @property
    def path(self):
        return join(settings.UPLOAD_DIR, self.name)

    def open_file(self):
        try:
            return open(self.path, self.mode)
        except IOError:
            if self.mode == 'rb':
                raise InexistentFile
            raise
                
    def encrypt_and_write(self, raw_data):
        if raw_data:
            block = self.cipher.encrypt(padding(raw_data))
            self.write(block)

    def chunks(self, chunk_size=None):
        ''' decrypting iterator '''

        if not chunk_size:
            chunk_size = self.DEFAULT_CHUNK_SIZE
        read = 0
        while True:
            block = self.read(chunk_size)
            if len(block) == 0:
                # EOF
                break
            block = self.cipher.decrypt(block)
            read += len(block)
            if read > self.size:
                # We remove the padding at the end of the file
                padding = self.size - read
                block = block[:padding]
            yield block


class EncryptedFileSystemStorage(FileSystemStorage):
    ''' handles encrypted files on disk with random names '''

    def __init__(self, location=settings.UPLOAD_DIR):
        super(EncryptedFileSystemStorage, self).__init__(location)

    def open(self, *args, **kwargs):
        return EncryptedUploadedFile(*args, **kwargs)
        
    def get_available_name(self):
        ''' return a random id for the upload file '''
        file_id = str(uuid4()).replace("-", "")
        return join(self.location, file_id)
