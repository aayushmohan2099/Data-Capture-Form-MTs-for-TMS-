# main/urls.py
from django.urls import path
from . import views, api

urlpatterns = [
    path('', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    # master trainer pages
    path('dashboard/master/', views.master_home, name='master_home'),
    path('capture/', views.capture_submission, name='capture_submission'),
    path('submission/<int:submission_pk>/resubmit/', views.resubmit_certificates, name='resubmit_certificates'),
    path("mt/change-password/", views.master_change_password, name="master_change_password"),
    # thematic expert pages
    path('dashboard/expert/', views.expert_home, name='expert_home'),
    path('expert/submission/<int:submission_pk>/', views.expert_submission_detail, name='expert_submission_detail'),
    path('dashboard/expert/approved/', views.expert_approved_trainers, name='expert_approved_trainers'),
    path('dashboard/expert/rejected/', views.expert_rejected_trainers, name='expert_rejected_trainers'),
    path('dashboard/expert/change-password/', views.expert_change_password, name='expert_change_password'),
    path('dashboard/expert/analytics/', views.expert_analytics, name='expert_analytics'),
    # optional: trainer detail view for TE-approved list (clickable rows)
    path('dashboard/expert/trainer/<int:trainer_pk>/', views.expert_trainer_detail, name='expert_trainer_detail'),
    # admin urls
    path('dashboard/admin/', views.admin_dashboard, name='admin_dashboard'),
    path('dashboard/admin/approved-trainers/', views.admin_approved_trainers, name='admin_approved_trainers'),
    path('dashboard/admin/approved-trainers/<int:trainer_pk>/', views.admin_trainer_detail, name='admin_trainer_detail'),
    path('dashboard/admin/export-trainers/', views.admin_export_trainers_csv, name='admin_export_trainers_csv'),
    path('dashboard/admin/users/', views.admin_users_list, name='admin_users_list'),
    path('dashboard/admin/users/create/', views.admin_user_create, name='admin_user_create'),
    path('dashboard/admin/users/<int:user_pk>/edit/', views.admin_user_edit, name='admin_user_edit'),
    # pending certificates admin view
    path('dashboard/admin/pending-certificates/', views.admin_pending_certificates, name='admin_pending_certificates'),
    path("dashboard/admin/rejected-trainers/", views.admin_rejected_trainers, name="admin_rejected_trainers"),
    path("dashboard/admin/all-submissions/", views.admin_all_submissions, name="admin_all_submissions"),
    path("dashboard/admin/change-password/", views.admin_change_password, name="admin_change_password"),
]

urlpatterns += [
    path('api/v1/approved-trainers/', api.approved_trainers_api, name='api_approved_trainers'),
]

urlpatterns += [
    path('signup/captcha/', views.signup_captcha, name='signup_captcha'),
    path('signup/', views.master_signup, name='master_signup'), 
]