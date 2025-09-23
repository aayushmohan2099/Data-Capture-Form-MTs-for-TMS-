# main/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils import timezone

# -------------------------
# Core user model
# -------------------------
class User(AbstractUser):
    ROLE_CHOICES = [
        ('thematic_expert', 'Thematic Expert'),
        ('master_trainer', 'Master Trainer'),
        ('admin', 'Admin'),
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='master_trainer')
    # allow master trainers to sign in by mobile; unique if present
    mobile = models.CharField("Mobile number", max_length=20, unique=True, blank=True, null=True, db_index=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        # prefer mobile display for master trainers
        if self.role == 'master_trainer' and self.mobile:
            return f"{self.mobile} ({self.get_role_display()})"
        return f"{self.username} ({self.get_role_display()})"


# -------------------------
# TrainingPlan
# -------------------------
class TrainingPlan(models.Model):
    training_name = models.CharField("Training name", max_length=255)
    theme = models.CharField("Theme", max_length=200, blank=True, null=True, db_index=True)
    # theme_expert: optional FK to a User who is a thematic expert
    theme_expert = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='training_plans',
        help_text="Thematic expert user for this training (optional)."
    )

    class Meta:
        verbose_name = "Training Plan"
        verbose_name_plural = "Training Plans"
        indexes = [
            models.Index(fields=['training_name']),
            models.Index(fields=['theme']),
        ]

    def __str__(self):
        return f"{self.training_name} ({self.theme})"


# -------------------------
# MasterTrainer (approved/published profile)
# -------------------------
class MasterTrainer(models.Model):
    # optional one-to-one link to User account (self-service login)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='master_trainer_profile',
        help_text="Optional link to User account for self-service login"
    )

    # Primary Fields
    full_name = models.CharField(max_length=200, db_index=True)
    profile_picture = models.ImageField(upload_to='trainer_pfps/', blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    mobile_no = models.CharField("Mobile No.", max_length=20, blank=True, null=True, db_index=True)
    aadhaar_no = models.CharField("Aadhaar No", max_length=20, blank=True, null=True)

    DISTRICT_CHOICES = [
        ('Agra', 'Agra'),
        ('Aligarh', 'Aligarh'),
        ('Allahabad (Prayagraj)', 'Allahabad (Prayagraj)'),
        ('Ambedkar Nagar', 'Ambedkar Nagar'),
        ('Amethi', 'Amethi'),
        ('Amroha', 'Amroha'),
        ('Auraiya', 'Auraiya'),
        ('Azamgarh', 'Azamgarh'),
        ('Baghpat', 'Baghpat'),
        ('Bahraich', 'Bahraich'),
        ('Ballia', 'Ballia'),
        ('Balrampur', 'Balrampur'),
        ('Banda', 'Banda'),
        ('Barabanki', 'Barabanki'),
        ('Bareilly', 'Bareilly'),
        ('Basti', 'Basti'),
        ('Bhadohi (Sant Ravidas Nagar)', 'Bhadohi (Sant Ravidas Nagar)'),
        ('Bijnor', 'Bijnor'),
        ('Budaun', 'Budaun'),
        ('Bulandshahr', 'Bulandshahr'),
        ('Chandauli', 'Chandauli'),
        ('Chitrakoot', 'Chitrakoot'),
        ('Deoria', 'Deoria'),
        ('Etah', 'Etah'),
        ('Etawah', 'Etawah'),
        ('Faizabad (Ayodhya)', 'Faizabad (Ayodhya)'),
        ('Farrukhabad', 'Farrukhabad'),
        ('Fatehpur', 'Fatehpur'),
        ('Firozabad', 'Firozabad'),
        ('Gautam Buddha Nagar (Noida)', 'Gautam Buddha Nagar (Noida)'),
        ('Ghaziabad', 'Ghaziabad'),
        ('Ghazipur', 'Ghazipur'),
        ('Gonda', 'Gonda'),
        ('Gorakhpur', 'Gorakhpur'),
        ('Hamirpur', 'Hamirpur'),
        ('Hapur', 'Hapur'),
        ('Hardoi', 'Hardoi'),
        ('Hathras', 'Hathras'),
        ('Jalaun', 'Jalaun'),
        ('Jaunpur', 'Jaunpur'),
        ('Jhansi', 'Jhansi'),
        ('Kannauj', 'Kannauj'),
        ('Kanpur Dehat', 'Kanpur Dehat'),
        ('Kanpur Nagar', 'Kanpur Nagar'),
        ('Kasganj', 'Kasganj'),
        ('Kaushambi', 'Kaushambi'),
        ('Kushinagar', 'Kushinagar'),
        ('Lakhimpur Kheri', 'Lakhimpur Kheri'),
        ('Lalitpur', 'Lalitpur'),
        ('Lucknow', 'Lucknow'),
        ('Maharajganj', 'Maharajganj'),
        ('Mahoba', 'Mahoba'),
        ('Mainpuri', 'Mainpuri'),
        ('Mathura', 'Mathura'),
        ('Mau', 'Mau'),
        ('Meerut', 'Meerut'),
        ('Mirzapur', 'Mirzapur'),
        ('Moradabad', 'Moradabad'),
        ('Muzaffarnagar', 'Muzaffarnagar'),
        ('Pilibhit', 'Pilibhit'),
        ('Pratapgarh', 'Pratapgarh'),
        ('Rae Bareli', 'Rae Bareli'),
        ('Rampur', 'Rampur'),
        ('Saharanpur', 'Saharanpur'),
        ('Sant Kabir Nagar', 'Sant Kabir Nagar'),
        ('Sant Ravidas Nagar', 'Sant Ravidas Nagar'),
        ('Shahjahanpur', 'Shahjahanpur'),
        ('Shamli', 'Shamli'),
        ('Shravasti', 'Shravasti'),
        ('Siddharthnagar', 'Siddharthnagar'),
        ('Sitapur', 'Sitapur'),
        ('Sonbhadra', 'Sonbhadra'),
        ('Sultanpur', 'Sultanpur'),
        ('Unnao', 'Unnao'),
        ('Varanasi', 'Varanasi'),
    ]

    empanel_district = models.CharField("Empanel District", max_length=255, choices =DISTRICT_CHOICES, blank=True, null=True)

    CATEGORY_CHOICES = [
        ('UR', 'General/Unreserved (UR)'),
        ('SC', 'Scheduled Castes (SC)'),
        ('ST', 'Scheduled Tribe (ST)'),
        ('OBC', 'Other Backward Class (OBC)')
    ]

    social_category = models.CharField("Social Category", max_length=50, choices=CATEGORY_CHOICES, blank=True, null=True)
    
    GENDER_CHOICES = [
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Others', 'Others')
    ]

    gender = models.CharField(max_length=20, choices=GENDER_CHOICES, blank=True, null=True)

    EDUCATION_CHOICES =[
        ('Under Graduate (UG)', 'Under Graduate (UG)'),
        ('Post Graduate (PG)', 'Post Graduate (PG)')
    ]

    education = models.CharField(max_length=200, choices=EDUCATION_CHOICES, blank=True, null=True)
    
    MARITAL_CHOICES = [
        ('Married', 'Married'),
        ('Unmarried', 'Unmarried'),
        ('Divorced/Widowed', 'Divorced/Widowed')
    ]

    marital_status = models.CharField(max_length=50, choices=MARITAL_CHOICES, blank=True, null=True)
    parent_or_spouse_name = models.CharField("Father/Mother/Spouse Name", max_length=200, blank=True, null=True)
    
    # Designation: DRP / SRP
    DESIGNATION_CHOICES = [
        ('DRP', 'DRP'),
        ('SRP', 'SRP'),
    ]
    designation = models.CharField("Designation", max_length=3, choices=DESIGNATION_CHOICES, blank=True, null=True, db_index=True)

    # Bank Details
    bank_account_number = models.CharField("Account Number", max_length=64, blank=True, null=True)
    ifsc = models.CharField("IFSC", max_length=32, blank=True, null=True)
    branch_name = models.CharField("Branch Name", max_length=200, blank=True, null=True)
    bank_name = models.CharField("Bank Name", max_length=200, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Master Trainer"
        verbose_name_plural = "Master Trainers"
        indexes = [
            models.Index(fields=['full_name']),
            models.Index(fields=['mobile_no']),
            models.Index(fields=['designation']),
        ]

    def __str__(self):
        return self.full_name


# -------------------------
# Submission (capture request) - versioned
# -------------------------
class MasterTrainerSubmission(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    trainer = models.ForeignKey(MasterTrainer, on_delete=models.CASCADE, related_name='submissions')
    full_name = models.CharField(max_length=200)
    date_of_birth = models.DateField(blank=True, null=True)
    mobile_no = models.CharField("Mobile No.", max_length=20, blank=True, null=True)
    aadhaar_no = models.CharField("Aadhaar No", max_length=20, blank=True, null=True)
    DISTRICT_CHOICES = [
        ('Agra', 'Agra'),
        ('Aligarh', 'Aligarh'),
        ('Allahabad (Prayagraj)', 'Allahabad (Prayagraj)'),
        ('Ambedkar Nagar', 'Ambedkar Nagar'),
        ('Amethi', 'Amethi'),
        ('Amroha', 'Amroha'),
        ('Auraiya', 'Auraiya'),
        ('Azamgarh', 'Azamgarh'),
        ('Baghpat', 'Baghpat'),
        ('Bahraich', 'Bahraich'),
        ('Ballia', 'Ballia'),
        ('Balrampur', 'Balrampur'),
        ('Banda', 'Banda'),
        ('Barabanki', 'Barabanki'),
        ('Bareilly', 'Bareilly'),
        ('Basti', 'Basti'),
        ('Bhadohi (Sant Ravidas Nagar)', 'Bhadohi (Sant Ravidas Nagar)'),
        ('Bijnor', 'Bijnor'),
        ('Budaun', 'Budaun'),
        ('Bulandshahr', 'Bulandshahr'),
        ('Chandauli', 'Chandauli'),
        ('Chitrakoot', 'Chitrakoot'),
        ('Deoria', 'Deoria'),
        ('Etah', 'Etah'),
        ('Etawah', 'Etawah'),
        ('Faizabad (Ayodhya)', 'Faizabad (Ayodhya)'),
        ('Farrukhabad', 'Farrukhabad'),
        ('Fatehpur', 'Fatehpur'),
        ('Firozabad', 'Firozabad'),
        ('Gautam Buddha Nagar (Noida)', 'Gautam Buddha Nagar (Noida)'),
        ('Ghaziabad', 'Ghaziabad'),
        ('Ghazipur', 'Ghazipur'),
        ('Gonda', 'Gonda'),
        ('Gorakhpur', 'Gorakhpur'),
        ('Hamirpur', 'Hamirpur'),
        ('Hapur', 'Hapur'),
        ('Hardoi', 'Hardoi'),
        ('Hathras', 'Hathras'),
        ('Jalaun', 'Jalaun'),
        ('Jaunpur', 'Jaunpur'),
        ('Jhansi', 'Jhansi'),
        ('Kannauj', 'Kannauj'),
        ('Kanpur Dehat', 'Kanpur Dehat'),
        ('Kanpur Nagar', 'Kanpur Nagar'),
        ('Kasganj', 'Kasganj'),
        ('Kaushambi', 'Kaushambi'),
        ('Kushinagar', 'Kushinagar'),
        ('Lakhimpur Kheri', 'Lakhimpur Kheri'),
        ('Lalitpur', 'Lalitpur'),
        ('Lucknow', 'Lucknow'),
        ('Maharajganj', 'Maharajganj'),
        ('Mahoba', 'Mahoba'),
        ('Mainpuri', 'Mainpuri'),
        ('Mathura', 'Mathura'),
        ('Mau', 'Mau'),
        ('Meerut', 'Meerut'),
        ('Mirzapur', 'Mirzapur'),
        ('Moradabad', 'Moradabad'),
        ('Muzaffarnagar', 'Muzaffarnagar'),
        ('Pilibhit', 'Pilibhit'),
        ('Pratapgarh', 'Pratapgarh'),
        ('Rae Bareli', 'Rae Bareli'),
        ('Rampur', 'Rampur'),
        ('Saharanpur', 'Saharanpur'),
        ('Sant Kabir Nagar', 'Sant Kabir Nagar'),
        ('Sant Ravidas Nagar', 'Sant Ravidas Nagar'),
        ('Shahjahanpur', 'Shahjahanpur'),
        ('Shamli', 'Shamli'),
        ('Shravasti', 'Shravasti'),
        ('Siddharthnagar', 'Siddharthnagar'),
        ('Sitapur', 'Sitapur'),
        ('Sonbhadra', 'Sonbhadra'),
        ('Sultanpur', 'Sultanpur'),
        ('Unnao', 'Unnao'),
        ('Varanasi', 'Varanasi'),
    ]

    empanel_district = models.CharField("Empanel District", max_length=255, choices =DISTRICT_CHOICES, blank=True, null=True)

    CATEGORY_CHOICES = [
        ('UR', 'General/Unreserved (UR)'),
        ('SC', 'Scheduled Castes (SC)'),
        ('ST', 'Scheduled Tribe (ST)'),
        ('OBC', 'Other Backward Class (OBC)')
    ]

    social_category = models.CharField("Social Category", max_length=50, choices=CATEGORY_CHOICES, blank=True, null=True)
    
    GENDER_CHOICES = [
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Others', 'Others')
    ]

    gender = models.CharField(max_length=20, choices=GENDER_CHOICES, blank=True, null=True)

    EDUCATION_CHOICES =[
        ('Under Graduate (UG)', 'Under Graduate (UG)'),
        ('Post Graduate (PG)', 'Post Graduate (PG)')
    ]

    education = models.CharField(max_length=200, choices=EDUCATION_CHOICES, blank=True, null=True)
    
    MARITAL_CHOICES = [
        ('Married', 'Married'),
        ('Unmarried', 'Unmarried'),
        ('Divorced/Widowed', 'Divorced/Widowed')
    ]

    marital_status = models.CharField(max_length=50, choices=MARITAL_CHOICES, blank=True, null=True)    
    parent_or_spouse_name = models.CharField("Father/Mother/Spouse Name", max_length=200, blank=True, null=True)

    # Submission-level designation (optional, mirrors MasterTrainer designation)
    DESIGNATION_CHOICES = [
        ('DRP', 'DRP'),
        ('SRP', 'SRP'),
    ]
    designation = models.CharField("Designation", max_length=3, choices=DESIGNATION_CHOICES, blank=True, null=True, db_index=True)

    bank_account_number = models.CharField("Account Number", max_length=64, blank=True, null=True)
    ifsc = models.CharField("IFSC", max_length=32, blank=True, null=True)
    branch_name = models.CharField("Branch Name", max_length=200, blank=True, null=True)
    bank_name = models.CharField("Bank Name", max_length=200, blank=True, null=True)

    other_achievements = models.TextField("Other Achievements", blank=True, null=True)
    success_stories = models.TextField("Success Stories", blank=True, null=True)

    training_plans = models.ManyToManyField(TrainingPlan, blank=True, related_name='submission_selected_by')

    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='pending', db_index=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(blank=True, null=True)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_submissions')
    rejection_reason = models.TextField(blank=True, null=True)

    # NEW: whether this submission's profile data was verified by the TE of the "first theme"
    profile_verified = models.BooleanField(default=False, db_index=True)
    profile_verified_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='profile_verified_submissions')
    profile_verified_at = models.DateTimeField(blank=True, null=True)

    rejection_authority = models.CharField("Rejection Authority", max_length=255, blank=True, null=True)

    class Meta:
        ordering = ('-submitted_at',)
        verbose_name = "Master Trainer Submission"
        verbose_name_plural = "Master Trainer Submissions"
        indexes = [
            models.Index(fields=['designation']),
        ]

    def __str__(self):
        return f"{self.trainer.full_name} - {self.status} ({self.submitted_at:%Y-%m-%d %H:%M})"


# -------------------------
# MasterTrainerCertificate
# -------------------------
class MasterTrainerCertificate(models.Model):
    CERT_STATUS = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('reverted', 'Reverted'),
    ]

    trainer_submission = models.ForeignKey(
        MasterTrainerSubmission, on_delete=models.CASCADE, related_name='certificates', null=True, blank=True,
        help_text="Certificates uploaded as part of a specific submission."
    )
    trainer = models.ForeignKey(
        MasterTrainer, on_delete=models.CASCADE, related_name='certificates', null=True, blank=True,
        help_text="Optional link to the approved trainer record."
    )

    certificate_number = models.CharField("Certificate Number", max_length=255, blank=True, null=True)
    training_module = models.ForeignKey(
        TrainingPlan,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='certificates',
        help_text="Link to the TrainingPlan record for which this certificate was issued (nullable)."
    )
    certificate_file = models.FileField(upload_to='trainer_certificates/', blank=True, null=True)
    issuing_authority = models.TextField("Issuing Authority", blank=True, null=True)
    issued_on = models.DateField("Issued on", blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    # NEW: per-certificate verification fields
    status = models.CharField(max_length=16, choices=CERT_STATUS, default='pending', db_index=True)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_certificates')
    reviewed_at = models.DateTimeField(blank=True, null=True)
    rejection_reason = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Master Trainer Certificate"
        verbose_name_plural = "Master Trainer Certificates"
        ordering = ('-created_at',)

    def __str__(self):
        label = self.certificate_number or (self.training_module.training_name if self.training_module else "Certificate")
        trainer_name = (self.trainer.full_name if self.trainer else
                        (self.trainer_submission.trainer.full_name if self.trainer_submission else "Unknown"))
        return f"{trainer_name} - {label}"


# -------------------------
# MasterTrainerAssignment (trainer <-> training plan)
# -------------------------
class MasterTrainerAssignment(models.Model):
    trainer = models.ForeignKey(MasterTrainer, on_delete=models.CASCADE, related_name='assignments')
    training_plan = models.ForeignKey(TrainingPlan, on_delete=models.CASCADE, related_name='assigned_trainers')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('trainer', 'training_plan')
        verbose_name = "Master Trainer Assignment"
        verbose_name_plural = "Master Trainer Assignments"

    def __str__(self):
        return f"{self.trainer.full_name} -> {self.training_plan.theme or self.training_plan.training_name}"
