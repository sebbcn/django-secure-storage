
import json

from django.http import HttpResponse, HttpResponseBadRequest
from django.http import StreamingHttpResponse
from django.http import HttpResponseServerError, Http404

from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from .forms import UploadFileForm, DownloadFileForm
from .upload_handlers import SecureFileUploadHandler
from .storage import EncryptedFileSystemStorage, InexistentFile


class SecureStorageView(View):

    def post(self, request, *args, **kwargs):

        try:
            form = self.get_form(request)
            if form.is_valid():
                response = self.get_response(request, form)
            else:
                content = json.dumps(dict(error=form.errors))
                response = HttpResponseBadRequest(content)

            return response

        except Exception, err:
            print err
            raise
            return HttpResponseServerError(err)


class UploadSecureStorageView(SecureStorageView):

    def get_form(self, request):
        return UploadFileForm(request.POST, request.FILES)

    def get_response(self, request, form):

        try:
            expire_on = request.FILES['file'].expire_date.isoformat()
        except AttributeError:
            expire_on = 'first download'
        content = json.dumps(dict(
            file_id=request.FILES['file'].name,
            size=request.FILES['file'].size,
            expire_on=expire_on))
        return HttpResponse(content, content_type='application/json')

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        request.upload_handlers = [SecureFileUploadHandler(), ]
        return super(UploadSecureStorageView, self).post(request, *args, **kwargs)


class DownloadSecureStorageView(SecureStorageView):

    def get_form(self, request):
        return DownloadFileForm(request.POST)

    def add_headers(self, response, content=None):

        # response['Content-Length'] = content.size or 0
        response['Content-Disposition'] = \
            'attachment; filename=%s' % content.clear_filename
        response['Content-Type'] = content.content_type
        return response

    def get_response(self, request, form):

        try:

            file_id = form.cleaned_data['file_id']
            passphrase = form.cleaned_data['passphrase']
            content = EncryptedFileSystemStorage()\
                .open(name=file_id, passphrase=passphrase, mode='rb')
            response = StreamingHttpResponse(streaming_content=content.chunks())
            return self.add_headers(response, content)

        except InexistentFile:
            raise Http404



