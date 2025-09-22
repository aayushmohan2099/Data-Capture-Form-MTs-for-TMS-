# main/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.http import HttpResponse
import csv
from django.urls import path, reverse
from django.db import transaction
import io
from django.shortcuts import render, redirect
from django.contrib import messages

from .models import (
    User,
    TrainingPlan,
    MasterTrainer,
    MasterTrainerSubmission,
    MasterTrainerCertificate,
    MasterTrainerAssignment,
)


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    # Add role/mobile to the default UserAdmin
    fieldsets = DjangoUserAdmin.fieldsets + (
        ('Role & Extra', {'fields': ('role', 'mobile')}),
    )
    list_display = ('username', 'mobile', 'email', 'role', 'is_staff', 'is_active')
    list_filter = ('role', 'is_staff', 'is_active')
    search_fields = ('username', 'mobile', 'email')


@admin.register(TrainingPlan)
class TrainingPlanAdmin(admin.ModelAdmin):
    list_display = ('training_name', 'theme', 'theme_expert')
    search_fields = ('training_name', 'theme')
    list_filter = ('theme',)

    change_list_template = "admin/trainingplan_change_list.html"  # optional: keeps default if you don't create this template

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('import-csv/', self.admin_site.admin_view(self.import_csv_view), name='trainingplan_import_csv'),
            path('download-blueprint/', self.admin_site.admin_view(self.download_blueprint), name='trainingplan_download_blueprint'),
        ]
        return custom_urls + urls

    def import_csv_view(self, request):
        """
        Admin view: upload CSV of training plans (training_name, theme).
        Upsert by training_name: create new or update theme if exists.
        """
        if request.method == 'POST' and request.FILES.get('csv_file'):
            csv_file = request.FILES['csv_file']
            try:
                raw = csv_file.read().decode('utf-8-sig')
            except AttributeError:
                # some uploaded files already provide a text stream
                raw = csv_file.read().decode('utf-8-sig')
            reader = csv.DictReader(io.StringIO(raw))
            required = {'training_name', 'theme'}
            headers = set([h.strip() for h in reader.fieldnames]) if reader.fieldnames else set()
            if not required.issubset(headers):
                messages.error(request, f"CSV must contain headers: {', '.join(required)}. Found: {', '.join(headers)}")
                return redirect('..')  # back to changelist

            created_count = 0
            updated_count = 0
            errors = []
            # Atomic to avoid partial writes in case of failure
            with transaction.atomic():
                for row_no, row in enumerate(reader, start=2):  # start=2 (header is row 1)
                    tname = (row.get('training_name') or '').strip()
                    theme = (row.get('theme') or '').strip()
                    if not tname:
                        errors.append(f"Row {row_no}: empty training_name, skipped.")
                        continue
                    try:
                        obj, created = TrainingPlan.objects.update_or_create(
                            training_name=tname,
                            defaults={'theme': theme or None}
                        )
                        if created:
                            created_count += 1
                        else:
                            updated_count += 1
                    except Exception as e:
                        errors.append(f"Row {row_no}: error saving '{tname}': {e}")
            # messages summary
            if created_count or updated_count:
                messages.success(request, f"Import complete. Created: {created_count}, Updated: {updated_count}.")
            if errors:
                for e in errors[:10]:
                    messages.warning(request, e)
                if len(errors) > 10:
                    messages.warning(request, f"And {len(errors)-10} more errors (see server logs).")
            return redirect('..')

        # GET - show upload form
        context = dict(
            self.admin_site.each_context(request),
        )
        return render(request, "admin/trainingplan_import.html", context)

    def download_blueprint(self, request):
        """
        Provide a CSV blueprint (headers + example rows) to download for correct upload format.
        """
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=trainingplan_blueprint.csv'
        writer = csv.writer(response)
        # headers: exactly what import expects
        writer.writerow(['training_name', 'theme'])
        # put a couple example rows
        writer.writerow(['Introduction to Nutrition', 'Nutrition'])
        writer.writerow(['Community Health Module 1', 'Community Health'])
        return response
    
@admin.register(MasterTrainer)
class MasterTrainerAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'mobile_no', 'empanel_district', 'created_at')
    search_fields = ('full_name', 'mobile_no', 'aadhaar_no')
    list_filter = ('empanel_district',)

    actions = ['export_as_csv']

    def export_as_csv(self, request, queryset):
        """
        Admin action: export selected MasterTrainer rows to CSV.
        """
        field_names = [
            'id', 'full_name', 'mobile_no', 'aadhaar_no',
            'bank_account_number', 'ifsc', 'bank_name', 'branch_name',
            'empanel_district', 'education', 'created_at'
        ]
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=master_trainers.csv'
        writer = csv.writer(response)
        writer.writerow(field_names)
        for obj in queryset:
            row = [getattr(obj, f, '') for f in field_names]
            writer.writerow(row)
        return response
    export_as_csv.short_description = "Export selected trainers as CSV"


@admin.register(MasterTrainerSubmission)
class MasterTrainerSubmissionAdmin(admin.ModelAdmin):
    list_display = ('trainer', 'status', 'submitted_at', 'reviewed_at', 'reviewed_by')
    list_filter = ('status',)
    search_fields = ('trainer__full_name', 'trainer__mobile_no', 'rejection_reason')


@admin.register(MasterTrainerCertificate)
class MasterTrainerCertificateAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'training_module', 'issued_on', 'created_at')
    search_fields = ('certificate_number', 'issuing_authority')


@admin.register(MasterTrainerAssignment)
class MasterTrainerAssignmentAdmin(admin.ModelAdmin):
    list_display = ('trainer', 'training_plan', 'created_at')
    search_fields = ('trainer__full_name', 'training_plan__training_name')
