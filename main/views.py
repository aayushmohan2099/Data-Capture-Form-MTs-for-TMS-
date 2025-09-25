# main/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.utils import timezone
from .forms import LoginForm, MasterTrainerSignupForm, MasterTrainerSubmissionForm, ChangePasswordForm
from .models import MasterTrainer, MasterTrainerSubmission, MasterTrainerCertificate, TrainingPlan
from django.http import HttpResponse
import csv
from functools import wraps
import re , json
from datetime import datetime
from django.db import transaction
from django.db.models import Count, Q
from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST
import random
User = get_user_model()


def login_view(request):
    """
    Combined page:
    - First choose user type, then enter identifier & password.
    - For master_trainer identifier is mobile; for others identifier is username.
    """
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            user_type = form.cleaned_data['user_type']
            identifier = form.cleaned_data['identifier'].strip()
            password = form.cleaned_data['password']

            user = None
            if user_type == 'master_trainer':
                # lookup by mobile
                try:
                    user = User.objects.get(mobile=identifier, role='master_trainer')
                except User.DoesNotExist:
                    user = None
            else:
                # admin or thematic expert: lookup by username and filter by role
                try:
                    user = User.objects.get(username=identifier, role=user_type)
                except User.DoesNotExist:
                    user = None

            if user and user.check_password(password):
                # successful
                auth_login(request, user)
                # Redirect based on role
                if user.role == 'admin':
                    return redirect('admin_dashboard')
                elif user.role == 'thematic_expert':
                    return redirect('expert_home')
                elif user.role == 'master_trainer':
                    return redirect('master_home')
                else:
                    return redirect('login')
            else:
                messages.error(request, "Invalid credentials for the selected user type.")
    else:
        form = LoginForm()

    return render(request, 'main/login.html', {'form': form})


@require_GET
def signup_captcha(request):
    """
    AJAX endpoint: generate a new simple arithmetic captcha question,
    store the numeric answer in session and return the question text as JSON.
    """
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    op = random.choice(['+', '-','*'])
    if op == '+':
        ans = a + b
        question = f"{a} + {b} = ?"
    elif op == '-':
        ans = a - b
        question = f"{a} - {b} = ?"
    else:
        ans = a * b
        question = f"{a} × {b} = ?"

    # store answer as string in session so comparison is straightforward
    request.session['signup_captcha_answer'] = str(ans)
    # optional: can set short expiry by storing timestamp and checking later
    return JsonResponse({'question': question})


def master_signup(request):
    """
    Keep your existing signup logic but include simple captcha server-side check.
    On GET: generate a question and put it into context as captcha_question.
    On POST: verify posted 'signup_captcha' matches session['signup_captcha_answer'] (pop it).
    """
    if request.method == 'GET':
        # create initial captcha for the form
        a = random.randint(1,9)
        b = random.randint(1,9)
        op = random.choice(['+','*'])
        if op == '+':
            question = f"{a} + {b} = ?"
            ans = a + b
        else:
            question = f"{a} × {b} = ?"
            ans = a * b
        request.session['signup_captcha_answer'] = str(ans)

        form = MasterTrainerSignupForm()
        return render(request, 'main/signup.html', {
            'form': form,
            'captcha_question': question,
        })

    # POST handling
    form = MasterTrainerSignupForm(request.POST)
    # validate captcha from session
    posted = request.POST.get('signup_captcha', '').strip()
    expected = request.session.pop('signup_captcha_answer', None)  # remove after read
    if expected is None:
        messages.error(request, "Captcha expired or missing. Please reload the page and try again.")
        # Recreate a new captcha so the template has one to show (GET behaviour)
        a = random.randint(1,9); b = random.randint(1,9); op = random.choice(['+','*'])
        if op == '+': question = f"{a} + {b} = ?"; ans = a + b
        else: question = f"{a} × {b} = ?"; ans = a * b
        request.session['signup_captcha_answer'] = str(ans)
        return render(request, 'main/signup.html', {'form': form, 'captcha_question': question})

    # posted must be numeric and match expected string
    if not posted or posted != expected:
        messages.error(request, "Captcha incorrect. Please try again.")
        # generate a fresh captcha for re-display
        a = random.randint(1,9); b = random.randint(1,9); op = random.choice(['+','*'])
        if op == '+': question = f"{a} + {b} = ?"; ans = a + b
        else: question = f"{a} × {b} = ?"; ans = a * b
        request.session['signup_captcha_answer'] = str(ans)
        return render(request, 'main/signup.html', {'form': form, 'captcha_question': question})

    # captcha OK -> continue with your existing signup flow:
    if form.is_valid():
        user, mt = form.save()
        # Instead of redirecting immediately, set a context flag so the template
        # shows the JS alert and then navigates to login.
        # Generate a fresh captcha (so page has something if user refreshes)
        a = random.randint(1,9); b = random.randint(1,9); op = random.choice(['+','*'])
        if op == '+': question = f"{a} + {b} = ?"; ans = a + b
        else: question = f"{a} × {b} = ?"; ans = a * b
        request.session['signup_captcha_answer'] = str(ans)

        # Render the same signup form template; the template will show the alert
        # and then redirect to login. (You might also clear the form or show a
        # fresh blank form if desired.)
        form = MasterTrainerSignupForm()  # blank form for re-render
        return render(request, 'main/signup.html', {
            'form': form,
            'captcha_question': question,
            'account_created': True,
        })
    else:
        # form invalid: re-render and regenerate captcha
        a = random.randint(1,9); b = random.randint(1,9); op = random.choice(['+','*'])
        if op == '+': question = f"{a} + {b} = ?"; ans = a + b
        else: question = f"{a} × {b} = ?"; ans = a * b
        request.session['signup_captcha_answer'] = str(ans)
        return render(request, 'main/signup.html', {'form': form, 'captcha_question': question})


@login_required
def logout_view(request):
    auth_logout(request)
    return redirect('login')


# small role-check helper
def role_required(role):
    def decorator(fn):
        from functools import wraps
        @wraps(fn)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('login')
            if getattr(request.user, 'role', None) != role:
                # unauthorized — send back to login or to their dashboard
                messages.error(request, "You do not have access to that page.")
                # send to their home if logged in
                if request.user.role == 'admin':
                    return redirect('admin_dashboard')
                if request.user.role == 'thematic_expert':
                    return redirect('expert_home')
                return redirect('master_home')
            return fn(request, *args, **kwargs)
        return wrapper
    return decorator


@login_required
def master_home(request):
    if request.user.role != 'master_trainer':
        messages.error(request, "Only Master Trainers can view this page.")
        return redirect('login')
    mt = MasterTrainer.objects.filter(user=request.user).first()
    submissions = mt.submissions.all().order_by('-submitted_at') if mt else []

    # Precompute display helpers to avoid calling filters in template
    submissions_list = []
    for s in submissions:
        # rejection authority label (if submission rejected)
        rej_label = None
        if s.status == 'rejected' and s.reviewed_by:
            rej_label = s.reviewed_by.get_full_name() or s.reviewed_by.username

        # reverted certificates: build a human-readable string if any exist
        rev_qs = s.certificates.filter(status='reverted').select_related('training_module')
        if rev_qs.exists():
            parts = []
            for c in rev_qs:
                if c.training_module and c.training_module.theme:
                    parts.append(f"Thematic expert of {c.training_module.theme}")
                else:
                    parts.append("Thematic expert (unassigned)")
            rev_display = ", ".join(parts)
        else:
            rev_display = None

        s.rejection_authority_label = rej_label
        s.reverted_themes_display = rev_display
        submissions_list.append(s)

    # pass submissions_list to template instead of raw queryset
    return render(request, 'main/master_home.html', {'profile': mt, 'submissions': submissions_list})

# CAPTURE (master trainer)
@login_required
def capture_submission(request):
    """
    Master trainer multi-tab capture. Certificates support multiple rows:
    each certificate row uses inputs named:
      certs-<index>-theme  (theme string)
      certs-<index>-module (trainingplan id or empty)
      certs-<index>-file   (file input)
    The template contains JS to add/remove rows and populate module drop-downs
    based on theme selection.
    """
    if not request.user.is_authenticated or request.user.role != 'master_trainer':
        messages.error(request, "Only Master Trainers can access the capture form.")
        return redirect('login')

    # ensure MasterTrainer profile exists (creates restful profile if missing)
    mt, _ = MasterTrainer.objects.get_or_create(
        user=request.user,
        defaults={'full_name': request.user.username, 'mobile_no': request.user.mobile or ''}
    )

    # Build theme/module mapping for template JS
    plans = TrainingPlan.objects.all().order_by('theme', 'training_name')
    modules_by_theme = {}
    themes = []
    for p in plans:
        raw_theme = (p.theme or 'Unassigned')
        # normalize theme key: trim and lowercase to avoid mismatches
        key = raw_theme.strip()
        norm_key = key.lower()
        if norm_key not in modules_by_theme:
            modules_by_theme[norm_key] = []
            themes.append(key)   # keep a display-friendly theme in themes list (non-normalized)
        modules_by_theme[norm_key].append({'id': p.id, 'name': p.training_name})

    # constants
    MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB

    if request.method == 'POST':
        # pass FILES in case form includes any FileFields (safe even if not)
        form = MasterTrainerSubmissionForm(request.POST, request.FILES)

        # debug: print posted field names and files so we can inspect what was sent
        print("DEBUG: POST keys:", list(request.POST.keys()))
        print("DEBUG: FILES keys:", list(request.FILES.keys()))

        # collect certificate indices from POST keys
        idx_set = set()
        for key in request.POST.keys():
            m = re.match(r'^certs-(\d+)-theme$', key)
            if m:
                idx_set.add(int(m.group(1)))
        indices = sorted(idx_set)

        # collect cert rows and prepare submitted_cert_rows for re-population if validation fails
        cert_rows = []
        submitted_cert_rows = []  # will be passed back to template (no file data)
        for i in indices:
            theme_val = request.POST.get(f'certs-{i}-theme', '').strip()
            module_val = request.POST.get(f'certs-{i}-module', '').strip()
            file_obj = request.FILES.get(f'certs-{i}-file')  # may be None
            cert_number = request.POST.get(f'certs-{i}-number', '').strip() or None
            issuing = request.POST.get(f'certs-{i}-issuing', '').strip() or None
            issued_on_raw = request.POST.get(f'certs-{i}-issued_on', '').strip() or None
            issued_on = None
            if issued_on_raw:
                # expected ISO YYYY-MM-DD from date input; fall back to try dd/mm/yyyy
                try:
                    issued_on = datetime.strptime(issued_on_raw, '%Y-%m-%d').date()
                except Exception:
                    try:
                        issued_on = datetime.strptime(issued_on_raw, '%d/%m/%Y').date()
                    except Exception:
                        issued_on = None

            cert_rows.append({
                'index': i,
                'theme': theme_val or None,
                'module_id': int(module_val) if module_val else None,
                'file': file_obj,
                'certificate_number': cert_number,
                'issuing_authority': issuing,
                'issued_on': issued_on,
                'issued_on_raw': issued_on_raw or '',
            })

            submitted_cert_rows.append({
                'theme': theme_val or '',
                'module_id': int(module_val) if module_val else None,
                'certificate_number': cert_number or '',
                'issuing_authority': issuing or '',
                'issued_on': issued_on_raw or '',
            })

        # server-side validation for certificates
        cert_errors = []
        if not cert_rows:
            cert_errors.append("At least one certificate row is required.")
        else:
            for idx, r in enumerate(cert_rows, start=1):
                label = f"Certificate row #{idx}"
                if not r.get('theme'):
                    cert_errors.append(f"{label}: Theme is required.")
                if not r.get('module_id'):
                    cert_errors.append(f"{label}: Module is required.")
                if not r.get('certificate_number'):
                    cert_errors.append(f"{label}: Certificate number is required.")
                if not r.get('issuing_authority'):
                    cert_errors.append(f"{label}: Issuing authority is required.")
                if not r.get('issued_on'):
                    cert_errors.append(f"{label}: Issued on date is required.")
                f = r.get('file')
                if not f:
                    cert_errors.append(f"{label}: Certificate file is required.")
                else:
                    # size check (guard if attribute missing)
                    try:
                        if hasattr(f, 'size') and f.size > MAX_FILE_BYTES:
                            cert_errors.append(f"{label}: File too large ({(f.size/1024/1024):.2f} MB). Maximum allowed is 10 MB.")
                    except Exception as ex:
                        print("Warning checking file size:", ex)
                    # type/extension check: allow pdf or images
                    name = getattr(f, 'name', '').lower()
                    content_type = getattr(f, 'content_type', '') or ''
                    if not (name.endswith('.pdf') or content_type.startswith('image/')):
                        cert_errors.append(f"{label}: Only PDF or image files are allowed.")

        # Validate form fields via Django form
        form_is_valid = form.is_valid()

        # If either form-level errors or certificate errors, show and re-render with submitted rows
        if not form_is_valid or cert_errors:
            # DEBUG: log errors to console
            print("DEBUG: form.errors (python repr):", form.errors)
            try:
                print("DEBUG: form.errors.as_json():", form.errors.as_json())
            except Exception:
                pass

            # attach user-friendly messages
            nf = form.non_field_errors()
            if nf:
                messages.error(request, "Form non-field errors: " + "; ".join(nf))
            for fname, ferr in form.errors.items():
                messages.error(request, f"{fname}: " + "; ".join(ferr))

            # attach certificate errors as form non-field errors (so template shows them)
            for ce in cert_errors:
                form.add_error(None, ce)
                messages.error(request, ce)

            messages.error(request, "Please fix the errors shown in the form below.")

            context = {
                'form': form,
                'trainer': mt,
                'themes': themes,
                'modules_by_theme_json': json.dumps(modules_by_theme),
                'submitted_cert_rows_json': json.dumps(submitted_cert_rows),
            }
            return render(request, 'main/capture.html', context)

        # all validation passed -> save submission + certs
        submission = form.save(commit=False)
        submission.trainer = mt
        submission.status = 'pending'
        submission.submitted_at = timezone.now()
        submission.save()
        form.save_m2m()

        cert_count = 0
        for r in cert_rows:
            f = r['file']
            if not f:
                continue
            module_obj = None
            if r['module_id']:
                module_obj = TrainingPlan.objects.filter(pk=r['module_id']).first()
            MasterTrainerCertificate.objects.create(
                trainer_submission=submission,
                trainer=None,
                training_module=module_obj,
                certificate_file=f,
                certificate_number=r.get('certificate_number'),
                issuing_authority=r.get('issuing_authority'),
                issued_on=r.get('issued_on'),
                status='pending'
            )
            cert_count += 1

        messages.success(request, f"Submission saved. {cert_count} certificate(s) uploaded and sent for review.")
        return redirect('master_home')

    else:
        # GET - prefill fields from existing mt if present
        initial = {
            'full_name': mt.full_name,
            'date_of_birth': mt.date_of_birth,
            'mobile_no': mt.mobile_no,
            'aadhaar_no': mt.aadhaar_no,
            'empanel_district': mt.empanel_district,
            'social_category': mt.social_category,
            'gender': mt.gender,
            'education': mt.education,
            'marital_status': mt.marital_status,
            'parent_or_spouse_name': mt.parent_or_spouse_name,
            'bank_account_number': mt.bank_account_number,
            'ifsc': mt.ifsc,
            'branch_name': mt.branch_name,
            'bank_name': mt.bank_name,
            'designation': mt.designation,
        }
        form = MasterTrainerSubmissionForm(initial=initial)

    context = {
        'form': form,
        'trainer': mt,
        'themes': themes,
        'modules_by_theme_json': json.dumps(modules_by_theme),
        'submitted_cert_rows_json': json.dumps([]),  # empty by default on GET
    }
    return render(request, 'main/capture.html', context)


@login_required
def master_home_list(request):
    """List of submissions for the logged-in master trainer"""
    if request.user.role != 'master_trainer':
        messages.error(request, "Only Master Trainers can view this page.")
        return redirect('login')

    try:
        mt = MasterTrainer.objects.get(user=request.user)
    except MasterTrainer.DoesNotExist:
        messages.info(request, "No profile found. Please create a submission first.")
        return redirect('capture_submission')

    submissions = mt.submissions.all().order_by('-submitted_at')
    return render(request, 'main/master_home.html', {'submissions': submissions})

# Master Trainer password change
@login_required
def master_change_password(request):
    if request.user.role != 'master_trainer':
        messages.error(request, "Only Master Trainers can change password.")
        return redirect('login')
    from .forms import ChangePasswordForm
    if request.method == 'POST':
        form = ChangePasswordForm(request.user, request.POST)
        if form.is_valid():
            request.user.set_password(form.cleaned_data['new_password'])
            request.user.save()
            messages.success(request, "Password updated. Please login again.")
            from django.contrib.auth import logout
            logout(request)
            return redirect('login')
    else:
        form = ChangePasswordForm(user=request.user)
    return render(request, 'main/master_change_password.html', {'form': form})


# --- Expert home: show pending certificates grouped by submission ---
@login_required
def expert_home(request):
    if request.user.role != 'thematic_expert':
        messages.error(request, "Only Thematic Experts can view this page.")
        return redirect('login')

    # We show submissions that have at least one certificate pending for which this user is the theme_expert
    pending_certs = MasterTrainerCertificate.objects.filter(
        status='pending',
        training_module__theme_expert=request.user
    ).select_related('trainer_submission', 'training_module')

    # Group by submission
    grouped = {}
    for c in pending_certs:
        sub = c.trainer_submission
        # safety: ignore certificates without submission (should not normally happen)
        if not sub:
            continue
        grouped.setdefault(sub, []).append(c)

    # Build a list of tuples (submission, certs_list, theme_text)
    groups_with_theme = []
    for sub, certs in grouped.items():
        # determine a sensible theme text from the first certificate that has a module->theme
        theme_text = ''
        for cert in certs:
            mod = getattr(cert, 'training_module', None)
            if not mod:
                continue
            # attempt multiple likely attribute names for theme and readable fields
            theme_obj = getattr(mod, 'theme', None)
            if theme_obj:
                # prefer common name fields; fall back to str()
                theme_text = (
                    getattr(theme_obj, 'theme_name', None) or
                    getattr(theme_obj, 'name', None) or
                    str(theme_obj)
                )
                break
        groups_with_theme.append((sub, certs, theme_text))

    # template now expects groups to be an iterable of (submission, certs, theme_text)
    return render(request, 'main/expert_home.html', {'groups': groups_with_theme})

@login_required
def expert_submission_detail(request, submission_pk):
    if request.user.role != 'thematic_expert':
        messages.error(request, "Only Thematic Experts can access this page.")
        return redirect('login')

    submission = get_object_or_404(MasterTrainerSubmission, pk=submission_pk)

    # Certificates in this submission that this TE is responsible for and are pending
    pending_certs_for_me = submission.certificates.filter(status='pending', training_module__theme_expert=request.user)

    if request.method == 'POST':
        action = request.POST.get('action')
        now = timezone.now()

        # --- APPROVE selected (existing behavior, but ensure submission finalization check) ---
        if action == 'approve':
            # approve only pending certs for this TE
            updated = pending_certs_for_me.update(status='approved', reviewed_by=request.user, reviewed_at=now, rejection_reason='')

            # If submission.profile_verified is False, this TE verifies the profile (first-theme rule)
            if not submission.profile_verified:
                mt = submission.trainer
                if not mt:
                    mt = MasterTrainer.objects.create(
                        full_name=submission.full_name or "Unknown",
                        mobile_no=submission.mobile_no or None,
                        date_of_birth=submission.date_of_birth
                    )
                    submission.trainer = mt
                # copy fields
                mt.full_name = submission.full_name
                mt.date_of_birth = submission.date_of_birth
                mt.mobile_no = submission.mobile_no
                mt.aadhaar_no = submission.aadhaar_no
                mt.empanel_district = submission.empanel_district
                mt.social_category = submission.social_category
                mt.gender = submission.gender
                mt.education = submission.education
                mt.marital_status = submission.marital_status
                mt.parent_or_spouse_name = submission.parent_or_spouse_name
                mt.bank_account_number = submission.bank_account_number
                mt.ifsc = submission.ifsc
                mt.branch_name = submission.branch_name
                mt.bank_name = submission.bank_name
                mt.designation = submission.designation
                mt.save()

                submission.profile_verified = True
                submission.profile_verified_by = request.user
                submission.profile_verified_at = now
                submission.save()

            # Link approved certs to the trainer record (if present)
            mt_for_link = submission.trainer
            if mt_for_link:
                submission.certificates.filter(status='approved', training_module__theme_expert=request.user).update(trainer=mt_for_link)

            # If NO certificates remain in pending or reverted states -> finalize submission as approved
            remaining = submission.certificates.filter(status__in=['pending', 'reverted']).exists()
            if not remaining:
                submission.status = 'approved'
                submission.reviewed_at = now
                submission.reviewed_by = request.user
                submission.save()

            messages.success(request, "Approved certificates for your theme. Profile verified if applicable.")
            return redirect('expert_home')

        # --- REVERT selected certificate(s) (new) ---
        elif action == 'revert':
            # Expect selected certificate ids from checkboxes named cert_ids
            cert_ids = request.POST.getlist('cert_ids')
            if not cert_ids:
                messages.error(request, "No certificate selected to revert.")
                return redirect('expert_submission_detail', submission_pk=submission_pk)

            # Only revert certs that belong to this submission AND to modules mapped to this TE
            qs = submission.certificates.filter(pk__in=cert_ids, training_module__theme_expert=request.user)
            if not qs.exists():
                messages.error(request, "No matching certificates found to revert.")
                return redirect('expert_submission_detail', submission_pk=submission_pk)

            now = timezone.now()
            qs.update(status='reverted', reviewed_by=request.user, reviewed_at=now, rejection_reason='Reverted for re-upload')

            messages.success(request, f"Reverted {qs.count()} certificate(s). The trainer will be asked to re-upload them.")
            return redirect('expert_home')

        # --- REJECT whole submission (existing behavior) ---
        elif action == 'reject':
            reason = request.POST.get('rejection_reason', '').strip()
            now = timezone.now()
            # mark all certificates (for this submission and theme) as rejected
            submission.certificates.filter(training_module__theme_expert=request.user, status='pending').update(
                status='rejected', reviewed_by=request.user, reviewed_at=now, rejection_reason=reason
            )
            # if profile not verified, mark submission rejected so MT must re-submit everything
            if not submission.profile_verified:
                submission.status = 'rejected'
                submission.reviewed_by = request.user
                submission.reviewed_at = now
                submission.rejection_reason = reason
                submission.save()
            messages.success(request, "Rejected the certificate(s) and submission if applicable.")
            return redirect('expert_home')

        else:
            messages.error(request, "Unknown action.")
            return redirect('expert_home')

    # GET - show submission + pending certs for this TE
    pending_certs_for_me = submission.certificates.filter(status='pending', training_module__theme_expert=request.user)
    return render(request, 'main/expert_submission_detail.html', {
        'submission': submission,
        'pending_certs': pending_certs_for_me,
    })


def expert_required(view_func):
    """Decorator ensuring the logged-in user is a thematic expert."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        if getattr(request.user, 'role', None) != 'thematic_expert':
            messages.error(request, "Only Thematic Experts may access that page.")
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return login_required(wrapper)


@expert_required
def expert_approved_trainers(request):
    """
    Trainers for which this TE has approved at least one certificate.
    Any TE who approved a certificate for a trainer will see that trainer here.
    """
    # find certificates approved by this TE that are linked to a trainer (or to a submission which links to a trainer)
    certs = MasterTrainerCertificate.objects.filter(status='approved', reviewed_by=request.user).select_related('trainer', 'trainer_submission')

    trainer_ids = set()
    trainers = []
    for c in certs:
        # prefer direct trainer link
        if c.trainer:
            t = c.trainer
        else:
            # fallback to trainer via submission
            t = getattr(getattr(c, 'trainer_submission', None), 'trainer', None)
        if t and t.id not in trainer_ids:
            trainer_ids.add(t.id)
            trainers.append(t)

    return render(request, 'main/expert_approved_trainers.html', {
        'trainers': trainers,
    })



@expert_required
def expert_rejected_trainers(request):
    """
    Submissions this TE rejected (submission.reviewed_by==user and status=='rejected').
    """
    subs = MasterTrainerSubmission.objects.filter(status='rejected', reviewed_by=request.user).select_related('trainer')
    return render(request, 'main/expert_rejected_trainers.html', {
        'submissions': subs,
    })


@expert_required
def expert_change_password(request):
    if request.method == 'POST':
        form = ChangePasswordForm(request.user, request.POST)
        if form.is_valid():
            new = form.cleaned_data['new_password']
            request.user.set_password(new)
            request.user.save()
            messages.success(request, "Password changed. Please log in again.")
            # after password change force logout and send to login
            from django.contrib.auth import logout
            logout(request)
            return redirect('login')
    else:
        form = ChangePasswordForm(user=request.user)
    return render(request, 'main/expert_change_password.html', {'form': form})


@expert_required
def expert_analytics(request):
    """
    For the TE, show counts of certificates submitted grouped by training plan (of themes where this TE is the theme_expert).
    Also show simple totals.
    """
    # training plans where this user is the theme_expert
    my_plans = TrainingPlan.objects.filter(theme_expert=request.user)
    # aggregate counts of certificates for those plans
    cert_counts = MasterTrainerCertificate.objects.filter(training_module__in=my_plans).values(
        'training_module'
    ).annotate(total=Count('id')).order_by('-total')

    # make a list of (training_plan, count)
    counts = []
    plan_map = {p.pk: p for p in my_plans}
    for row in cert_counts:
        pid = row['training_module']
        p = plan_map.get(pid)
        if p:
            counts.append({'plan': p, 'count': row['total']})

    # also provide totals
    total_submitted = sum(r['count'] for r in counts) if counts else 0

    return render(request, 'main/expert_analytics.html', {
        'counts': counts,
        'total_submitted': total_submitted,
        'my_plans': my_plans,
    })


@expert_required
def expert_trainer_detail(request, trainer_pk):
    # show the trainer profile in read-only form (for TE to view)
    trainer = get_object_or_404(MasterTrainer, pk=trainer_pk)
    # show submissions and certificates for that trainer (limited)
    subs = trainer.submissions.all().order_by('-submitted_at')
    certs = trainer.certificates.all().order_by('-created_at')
    return render(request, 'main/expert_trainer_detail.html', {
        'trainer': trainer,
        'submissions': subs,
        'certificates': certs,
    })

@login_required
def resubmit_certificates(request, submission_pk):
    # Only master trainer who owns the submission may resubmit for reverted certs
    if request.user.role != 'master_trainer':
        messages.error(request, "Only Master Trainers can resubmit certificates.")
        return redirect('login')

    submission = get_object_or_404(MasterTrainerSubmission, pk=submission_pk)

    # ensure this submission belongs to the logged-in MT
    mt = MasterTrainer.objects.filter(user=request.user).first()
    if not mt or submission.trainer_id != mt.id:
        messages.error(request, "You do not have permission to edit that submission.")
        return redirect('master_home')

    # list of certificate rows with status 'reverted'
    reverted_certs = list(submission.certificates.filter(status='reverted').select_related('training_module'))

    # provide all training plans for module select
    all_plans = list(TrainingPlan.objects.all().order_by('theme', 'training_name'))

    if request.method == 'POST':
        # Expect file inputs named resub-<cert_pk>-file and other fields
        uploaded_any = False
        created_count = 0

        try:
            with transaction.atomic():
                for cert in reverted_certs:
                    file_field_name = f'resub-{cert.pk}-file'
                    file_obj = request.FILES.get(file_field_name)
                    # if no file uploaded for this cert, skip it (user may only replace some)
                    if not file_obj:
                        continue

                    # read other metadata fields (may be empty)
                    module_val = request.POST.get(f'resub-{cert.pk}-module', '').strip() or None
                    cert_number = request.POST.get(f'resub-{cert.pk}-number', '').strip() or None
                    issuing = request.POST.get(f'resub-{cert.pk}-issuing', '').strip() or None
                    issued_on_raw = request.POST.get(f'resub-{cert.pk}-issued_on', '').strip() or None
                    issued_on = None
                    if issued_on_raw:
                        # try parse YYYY-MM-DD first
                        try:
                            issued_on = datetime.strptime(issued_on_raw, '%Y-%m-%d').date()
                        except Exception:
                            try:
                                issued_on = datetime.strptime(issued_on_raw, '%d/%m/%Y').date()
                            except Exception:
                                issued_on = None

                    # resolve module object if provided
                    module_obj = None
                    if module_val:
                        try:
                            module_obj = TrainingPlan.objects.filter(pk=int(module_val)).first()
                        except Exception:
                            module_obj = None

                    # delete old file (if any) and old database row
                    try:
                        if cert.certificate_file:
                            cert.certificate_file.delete(save=False)
                    except Exception as e:
                        # non-fatal; log for debugging
                        print(f"Warning deleting old cert file: {e}")

                    cert.delete()

                    # create new certificate row carrying metadata
                    MasterTrainerCertificate.objects.create(
                        trainer_submission=submission,
                        trainer=None,
                        training_module=module_obj,
                        certificate_file=file_obj,
                        certificate_number=cert_number,
                        issuing_authority=issuing,
                        issued_on=issued_on,
                        status='pending'
                    )
                    uploaded_any = True
                    created_count += 1

                if uploaded_any:
                    # ensure the submission remains pending and clears any final rejection flags
                    submission.status = 'pending'
                    submission.rejection_reason = ''
                    submission.reviewed_at = None
                    submission.reviewed_by = None
                    submission.save()
        except Exception as e:
            print("Error during resubmit processing:", e)
            messages.error(request, "Failed to process resubmission — try again or contact admin.")
            return redirect('master_home')

        if uploaded_any:
            messages.success(request, f"Uploaded {created_count} replacement certificate(s). Sent for re-review.")
        else:
            messages.info(request, "No files uploaded. Nothing changed.")
        return redirect('master_home')

    # GET: render upload form for each reverted cert
    return render(request, 'main/resubmit_certificates.html', {
        'submission': submission,
        'reverted_certs': reverted_certs,
        'all_plans': all_plans,
    })

def admin_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        if getattr(request.user, 'role', None) != 'admin':
            messages.error(request, "Admin access required.")
            # redirect to appropriate home
            if request.user.role == 'thematic_expert':
                return redirect('expert_home')
            if request.user.role == 'master_trainer':
                return redirect('master_home')
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return _wrapped


@admin_required
def admin_dashboard(request):
    """
    Admin landing page: quick links to all admin panels.
    Approved trainers = MasterTrainer records that were created/confirmed from a verified submission.
    """
    # trainers that are linked from a verified submission
    verified_trainers_qs = MasterTrainer.objects.filter(submissions__profile_verified=True).distinct()

    total_trainers = MasterTrainer.objects.count()
    approved_trainers = verified_trainers_qs.count()
    total_users = User.objects.count()
    pending_certs = MasterTrainerCertificate.objects.filter(status='pending').count()

    context = {
        'total_trainers': total_trainers,
        'approved_trainers': approved_trainers,
        'total_users': total_users,
        'pending_certs': pending_certs,
    }
    return render(request, 'main/admin_dashboard.html', context)


@admin_required
def admin_approved_trainers(request):
    """
    Admin view: list of approved trainers (MasterTrainer records that were verified via a submission).
    Each row links to a profile detail page.
    Shows designation and the theme of the trainer's first uploaded certificate.
    """
    # Query approved trainers
    trainers_qs = MasterTrainer.objects.filter(submissions__profile_verified=True).distinct().order_by('full_name')

    # Build a list of dicts with trainer + computed first_theme
    trainers = []
    for t in trainers_qs:
        # attempt to get the earliest certificate for this trainer
        first_cert = t.certificates.all().order_by('created_at').first()
        first_theme = None
        if first_cert and first_cert.training_module:
            # training_module.theme is a plain string on the TrainingPlan model
            first_theme = first_cert.training_module.theme or None

        trainers.append({
            'trainer': t,
            'designation': t.designation,
            'first_theme': first_theme or '-',
        })

    return render(request, 'main/admin_approved_trainers.html', {'trainers': trainers})


@admin_required
def admin_trainer_detail(request, trainer_pk):
    """
    Show full profile for a single approved MasterTrainer (clickable from approved list).
    Only allow detail for trainers that are actually in the "approved" set (verified).
    """
    trainer = get_object_or_404(MasterTrainer, pk=trainer_pk,
                                submissions__profile_verified=True)  # ensures only verified trainers visible

    # get related submissions and certificates for display
    submissions = trainer.submissions.all().order_by('-submitted_at')
    certificates = trainer.certificates.all().order_by('-created_at')

    return render(request, 'main/admin_trainer_detail.html', {
        'trainer': trainer,
        'submissions': submissions,
        'certificates': certificates,
    })

@admin_required
def admin_pending_certificates(request):
    """
    Show master trainer submissions that currently have pending certificates,
    and list the unique thematic expert usernames (for themes) that must approve them.
    """
    # submissions that have at least one pending certificate
    subs_qs = MasterTrainerSubmission.objects.filter(certificates__status='pending').distinct().order_by('-submitted_at')

    # Build list entries with the submission and the set of TE usernames required
    entries = []
    for s in subs_qs:
        # training modules for pending certs
        pending_certs = s.certificates.filter(status='pending').select_related('training_module__theme_expert')
        # collect theme_expert usernames (skip null)
        te_usernames = []
        for c in pending_certs:
            te = getattr(getattr(c, 'training_module', None), 'theme_expert', None)
            if te:
                uname = te.username
            else:
                uname = None
            if uname and uname not in te_usernames:
                te_usernames.append(uname)
        entries.append({
            'submission': s,
            'trainer_mobile': s.trainer.mobile_no if s.trainer else None,
            'submission_id': s.pk,
            'submission_status': s.status,
            'pending_cert_count': pending_certs.count(),
            'theme_expert_usernames': te_usernames or ['(unassigned)'],
        })

    return render(request, 'main/admin_pending_certificates.html', {'entries': entries})

@admin_required
def admin_export_trainers_csv(request):
    """
    Export approved trainers as CSV. Exports ALL approved trainers.
    """
    qs = MasterTrainer.objects.filter(submissions__profile_verified=True).order_by('id')

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename=approved_trainers.csv'
    writer = csv.writer(response)
    headers = [
        'id', 'full_name', 'mobile_no', 'aadhaar_no', 'empanel_district',
        'designation', 'first_theme',
        'bank_account_number', 'ifsc', 'branch_name', 'bank_name',
        'education', 'created_at'
    ]
    writer.writerow(headers)
    for t in qs:
        # compute first_theme similar to list view
        first_cert = t.certificates.all().order_by('created_at').first()
        first_theme = first_cert.training_module.theme if (first_cert and first_cert.training_module) else ''
        writer.writerow([
            t.id, t.full_name, t.mobile_no, t.aadhaar_no, t.empanel_district,
            t.designation or '', first_theme,
            t.bank_account_number, t.ifsc, t.branch_name, t.bank_name,
            t.education, t.created_at.isoformat() if t.created_at else ''
        ])
    return response



@admin_required
def admin_users_list(request):
    """
    List all users with quick actions: edit / change password / create new.
    """
    qs = User.objects.all().order_by('username')
    return render(request, 'main/admin_users_list.html', {'users': qs})


@admin_required
def admin_user_create(request):
    from .forms import AdminUserCreateForm
    if request.method == 'POST':
        form = AdminUserCreateForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "User created.")
            return redirect('admin_users_list')
    else:
        form = AdminUserCreateForm()
    return render(request, 'main/admin_user_create.html', {'form': form})


@admin_required
def admin_user_edit(request, user_pk):
    from .forms import AdminUserUpdateForm, AdminUserPasswordForm
    user_obj = get_object_or_404(User, pk=user_pk)
    if request.method == 'POST':
        if 'update_profile' in request.POST:
            form = AdminUserUpdateForm(request.POST, instance=user_obj)
            if form.is_valid():
                form.save()
                messages.success(request, "User updated.")
                return redirect('admin_users_list')
        elif 'set_password' in request.POST:
            pwd_form = AdminUserPasswordForm(request.POST)
            if pwd_form.is_valid():
                user_obj.set_password(pwd_form.cleaned_data['password'])
                user_obj.save()
                messages.success(request, "Password updated.")
                return redirect('admin_users_list')
    else:
        form = AdminUserUpdateForm(instance=user_obj)
        pwd_form = AdminUserPasswordForm()
    return render(request, 'main/admin_user_edit.html', {'form': form, 'pwd_form': pwd_form, 'user_obj': user_obj})

# Admin rejected trainers
@admin_required
def admin_rejected_trainers(request):
    subs = MasterTrainerSubmission.objects.filter(status='rejected').select_related('trainer')
    return render(request, 'main/admin_rejected_trainers.html', {'submissions': subs})

# Admin all submissions
@admin_required
def admin_all_submissions(request):
    subs = MasterTrainerSubmission.objects.all().order_by('-submitted_at')
    return render(request, 'main/admin_all_submissions.html', {'submissions': subs})

# Admin change password
@admin_required
def admin_change_password(request):
    from .forms import ChangePasswordForm
    if request.method == 'POST':
        form = ChangePasswordForm(request.user, request.POST)
        if form.is_valid():
            request.user.set_password(form.cleaned_data['new_password'])
            request.user.save()
            messages.success(request, "Password updated. Please login again.")
            from django.contrib.auth import logout
            logout(request)
            return redirect('login')
    else:
        form = ChangePasswordForm(user=request.user)
    return render(request, 'main/admin_change_password.html', {'form': form})