from os import listdir, unlink
from os.path import join
from django.core.management.base import BaseCommand, CommandError
from secure_storage.models import EncryptedUploadedFileMetaData
from secure_storage import app_settings 

class Command(BaseCommand):
    help = 'Removes all the expired files'

    def handle(self, *args, **options):

        for f in listdir(app_settings.UPLOAD_DIR):
            if not EncryptedUploadedFileMetaData.objects.filter(file_id=f).exists():
                self.stdout.write('Removing file %s' % f)
                unlink(join(app_settings.UPLOAD_DIR,f))
