import pickle
from django.db import models
from .encryption import get_cipher_and_iv, padding
from django.utils.timezone import now


class EncryptedUploadedFileMetaData(models.Model):

    file_id = models.CharField(max_length=50, primary_key=True)
    encrypted_name = models.CharField(max_length=200)
    iv = models.CharField(max_length=50)
    expire_date = models.DateTimeField(auto_now=False, null=True, blank=True)
    one_time = models.BooleanField(default=False)
    size = models.IntegerField(default=0, null=True, blank=True)

    @classmethod
    def save_(cls, file_):

        cipher = get_cipher_and_iv(file_.passphrase, file_.iv)[0]
        encrypted_name = cipher.encrypt(
            padding(file_.clear_filename + '|' + file_.content_type))

        metadata = cls()
        metadata.file_id = file_.name

        for attr in ('size', 'one_time', 'iv', 'expire_date'):
            setattr(metadata, attr, getattr(file_, attr, None))
        metadata.encrypted_name = pickle.dumps(encrypted_name)
        metadata.iv = pickle.dumps(metadata.iv)
        metadata.save()
        return metadata

    @classmethod
    def update(cls, file_, **kwargs):

        from .storage import InexistentFile
        try:
            metadata = cls.objects.get(
                file_id=file_.name)
        except cls.DoesNotExist:
            raise InexistentFile
        for arg, val in kwargs.items():
            setattr(metadata, arg, val)
        metadata.save()

    @classmethod
    def load(cls, file_):

        from .storage import InexistentFile, ExpiredFile
        try:
            metadata = cls.objects.get(
                file_id=file_.name)
        except cls.DoesNotExist:
            raise InexistentFile

        for attr in ('size', 'one_time', 'iv', 'expire_date'):
            setattr(file_, attr, getattr(metadata, attr, None))

        file_.iv = pickle.loads(file_.iv)
        cipher = get_cipher_and_iv(file_.passphrase, file_.iv)[0]
        encrypted_name = pickle.loads(metadata.encrypted_name)
        file_.clear_filename, file_.content_type = \
            cipher.decrypt(encrypted_name).split('|')

        if file_.expire_date and file_.expire_date < now():
            metadata.delete()
            raise ExpiredFile('This file has expired')

        if file_.one_time:
            metadata.delete()
