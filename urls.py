from django.conf.urls import patterns, url
from .views import UploadSecureStorageView, DownloadSecureStorageView

urlpatterns = patterns(
    '',
    url(r'^upload/$',
        UploadSecureStorageView.as_view(),
        name='secure-storage-upload'),

    url(r'^download/$',
        DownloadSecureStorageView.as_view(),
        name='secure-storage-download'),
)
