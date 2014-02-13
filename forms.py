from django import forms
from django.core.exceptions import ValidationError
from app_settings import EXPIRATION_CHOICES


class DownloadFileForm(forms.Form):

    file_id = forms.CharField(
        max_length=32,
        required=True
    )

    passphrase = forms.CharField(
        max_length=100,
        required=True,
    )


class UploadFileForm(forms.Form):

    passphrase = forms.CharField(
        max_length=100,
        required=True,
    )
    expire_date = forms.ChoiceField(
        choices=EXPIRATION_CHOICES,
    )

    file = forms.FileField(
        required=True,
        allow_empty_file=True,
    )

    def clean_expire_date(self):

        date = self.cleaned_data['expire_date']
        try:
            date_ = int(date)
        except ValueError:
            raise ValueError('Invalid Expiration date')

        if date_ not in (e[0] for e in EXPIRATION_CHOICES):
            raise ValueError('Invalid Expiration date')

        return date

    def clean_passphrase(self):

        passphrase = self.cleaned_data['passphrase']

        if len(passphrase) < 20:
            raise ValidationError('Passphrase must be at least 20 chars long.')
        return passphrase

