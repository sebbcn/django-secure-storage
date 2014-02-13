
from os.path import join
from django.conf import settings

UPLOAD_DIR = join(settings.MEDIA_ROOT, 'secure_storage')

UPLOAD_FILE_SIZE_LIMIT = 100 * 1024 * 1024

UPLOAD_DOMAIN = 'http://localhost:8000'


ONE_TIME, ONE_MINUTE, ONE_HOUR, ONE_DAY, ONE_WEEK, ONE_MONTH, ONE_YEAR, FOREVER = (
    0, 60, 3600, 86400, 604800, 2592000, 31536000, -1)
EXPIRATION_CHOICES = (
        (ONE_TIME, 'One-time download'),
        (ONE_HOUR, 'One hour'),
        (ONE_DAY, 'One day'),
        (ONE_WEEK, 'One week'),
        (ONE_MONTH, 'One month'),
        (ONE_YEAR, 'One year'),
        (FOREVER, 'Forever'))

