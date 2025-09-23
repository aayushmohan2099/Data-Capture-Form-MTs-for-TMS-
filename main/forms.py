# main/forms.py
from django import forms
from django.core.exceptions import ValidationError
from .models import User, MasterTrainer, MasterTrainerSubmission, MasterTrainerCertificate, TrainingPlan
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
import re
from django.core.exceptions import ValidationError

User = get_user_model()

USER_TYPE_CHOICES = [
    ('master_trainer', 'Master Trainer'),
    ('thematic_expert', 'Thematic Expert'),
    ('admin', 'Admin'),
]


class LoginForm(forms.Form):
    user_type = forms.ChoiceField(choices=USER_TYPE_CHOICES, widget=forms.Select(attrs={'id': 'id_user_type'}))
    identifier = forms.CharField(label='Username / Mobile', widget=forms.TextInput(attrs={'id': 'id_identifier'}))
    password = forms.CharField(widget=forms.PasswordInput)


class MasterTrainerSignupForm(forms.Form):
    mobile = forms.CharField(max_length=20)
    password = forms.CharField(widget=forms.PasswordInput)
    full_name = forms.CharField(max_length=200, required=False)

    def clean_mobile(self):
        mobile = self.cleaned_data['mobile'].strip()
        if User.objects.filter(mobile=mobile).exists():
            raise ValidationError("This mobile number is already registered.")
        elif not re.match(r'^\d{10}$', mobile):
            raise ValidationError("Mobile number must be exactly 10 digits.")
        return mobile

    def save(self):
        mobile = self.cleaned_data['mobile'].strip()
        username = mobile
        password = self.cleaned_data['password']
        full_name = self.cleaned_data.get('full_name') or ''
        user = User.objects.create(username=username, mobile=mobile, role='master_trainer')
        user.set_password(password)
        user.save()
        # Creating a blank MasterTrainer profile and link
        mt = MasterTrainer.objects.create(user=user, full_name=full_name, mobile_no=mobile)
        return user, mt


class MasterTrainerSubmissionForm(forms.ModelForm):
    training_plans = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False,
        widget=forms.CheckboxSelectMultiple
    )

    date_of_birth = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'type': 'date', 'placeholder': 'YYYY-MM-DD'}),
        input_formats=['%Y-%m-%d', '%d/%m/%Y']  
    )

    class Meta:
        model = MasterTrainerSubmission
        fields = [
            'full_name', 'date_of_birth', 'mobile_no', 'aadhaar_no',
            'empanel_district', 'social_category', 'gender', 'education',
            'marital_status', 'parent_or_spouse_name', 'designation', 
            'bank_account_number', 'ifsc', 'branch_name', 'bank_name',
            'other_achievements', 'success_stories', 'training_plans'
        ]
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # set queryset lazily to avoid import issues at module load
        from .models import TrainingPlan
        self.fields['training_plans'].queryset = TrainingPlan.objects.all()
    
    # --- Custom field validations ---

    def clean_full_name(self):
        full_name = self.cleaned_data.get('full_name')
        if not full_name:
            return full_name  # let blank/null pass if allowed
        full_name = full_name.strip()
        if not re.match(r'^[A-Z ]+$', full_name):
            raise ValidationError("Full Name must contain only capital letters (A-Z).")
        return full_name

    def clean_mobile_no(self):
        mobile = self.cleaned_data.get('mobile_no')
        if not mobile:
            return mobile
        mobile = mobile.strip()
        if not re.match(r'^\d{10}$', mobile):
            raise ValidationError("Mobile number must be exactly 10 digits.")
        return mobile

    def clean_aadhaar_no(self):
        aadhaar = self.cleaned_data.get('aadhaar_no')
        if not aadhaar:
            return aadhaar
        aadhaar = aadhaar.strip()
        if not re.match(r'^\d{12}$', aadhaar):
            raise ValidationError("Aadhaar number must be exactly 12 digits.")
        return aadhaar

    def clean_branch_name(self):
        branch = self.cleaned_data.get('branch_name')
        if not branch:
            return branch
        branch = branch.strip()
        if not re.match(r'^[A-Z ]+$', branch):
            raise ValidationError("Branch Name must contain only uppercase alphabets.")
        return branch

    def clean_bank_name(self):
        bank = self.cleaned_data.get('bank_name')
        if not bank:
            return bank
        bank = bank.strip()
        if not re.match(r'^[A-Z ]+$', bank):
            raise ValidationError("Bank Name must contain only uppercase alphabets.")
        return bank

    def clean_other_achievements(self):
        achievements = self.cleaned_data.get('other_achievements')
        if not achievements:
            return achievements
        word_count = len(achievements.split())
        if word_count > 200:
            raise ValidationError("Other achievements must not exceed 200 words.")
        return achievements

    def clean_success_stories(self):
        stories = self.cleaned_data.get('success_stories')
        if not stories:
            return stories
        word_count = len(stories.split())
        if word_count > 200:
            raise ValidationError("Success stories must not exceed 200 words.")
        return stories

class AdminUserCreateForm(forms.ModelForm):
    """
    Create a new user (admin/thematic_expert/master_trainer).
    For master_trainer you may optionally set mobile; username is required.
    """
    password = forms.CharField(widget=forms.PasswordInput, required=True, help_text="Set a password for the user.")

    class Meta:
        model = User
        fields = ['username', 'mobile', 'email', 'role', 'is_staff', 'is_active']

    def save(self, commit=True):
        pwd = self.cleaned_data.pop('password')
        user = super().save(commit=False)
        user.set_password(pwd)
        if commit:
            user.save()
        return user


class AdminUserUpdateForm(forms.ModelForm):
    """
    Admin can update username, mobile, email, role, is_active/is_staff.
    Password is handled separately.
    """
    class Meta:
        model = User
        fields = ['username', 'mobile', 'email', 'role', 'is_staff', 'is_active']


class AdminUserPasswordForm(forms.Form):
    """
    Set or reset a user's password.
    """
    password = forms.CharField(widget=forms.PasswordInput, required=True)
    password_confirm = forms.CharField(widget=forms.PasswordInput, required=True)

    def clean(self):
        cleaned = super().clean()
        p = cleaned.get('password')
        pc = cleaned.get('password_confirm')
        if p and pc and p != pc:
            raise forms.ValidationError("Passwords do not match.")
        return cleaned        
    

class ChangePasswordForm(forms.Form):
    current_password = forms.CharField(widget=forms.PasswordInput, required=True, label="Current password")
    new_password = forms.CharField(widget=forms.PasswordInput, required=True, label="New password")
    new_password_confirm = forms.CharField(widget=forms.PasswordInput, required=True, label="Confirm new password")

    def __init__(self, user=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def clean(self):
        cleaned = super().clean()
        cur = cleaned.get('current_password')
        n = cleaned.get('new_password')
        nc = cleaned.get('new_password_confirm')
        if not self.user:
            raise forms.ValidationError("User not supplied.")
        if cur and not self.user.check_password(cur):
            raise forms.ValidationError("Current password is incorrect.")
        if n and nc and n != nc:
            raise forms.ValidationError("New passwords do not match.")
        return cleaned