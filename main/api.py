# main/api.py
from django.core.paginator import Paginator, EmptyPage
from django.http import JsonResponse
from django.db.models import Prefetch
from django.urls import reverse
from .models import MasterTrainer, MasterTrainerCertificate, TrainingPlan
import math

# Pagination defaults
DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

def _int_or(value, default):
    try:
        return int(value)
    except Exception:
        return default

def _build_page_url(request, page, page_size):
    # Build URL preserving query params except page
    params = request.GET.copy()
    params['page'] = page
    params['page_size'] = page_size
    return request.build_absolute_uri(f"{request.path}?{params.urlencode()}")

def _serialize_certificate(c):
    module = getattr(c, 'training_module', None)
    module_data = None
    if module:
        module_data = {
            'id': module.id,
            'training_name': module.training_name,
            'theme': module.theme,
        }
    file_url = None
    try:
        if c.certificate_file:
            file_url = c.certificate_file.url
    except Exception:
        file_url = None

    return {
        'id': c.id,
        'certificate_number': c.certificate_number,
        'certificate_file_url': file_url,
        'issuing_authority': c.issuing_authority,
        'issued_on': (c.issued_on.isoformat() if c.issued_on else None),
        'training_module': module_data,
        'status': c.status,
        'reviewed_by': (c.reviewed_by.username if c.reviewed_by else None),
        'reviewed_at': (c.reviewed_at.isoformat() if c.reviewed_at else None),
    }

def _serialize_trainer(trainer):
    # use prefetched approved certificates if available
    certs = []
    # prefer attribute produced by Prefetch (see view)
    prefetched = getattr(trainer, 'approved_certificates_prefetched', None)
    if prefetched is not None:
        certs_qs = prefetched
    else:
        certs_qs = trainer.certificates.filter(status='approved').select_related('training_module')

    for c in certs_qs:
        certs.append(_serialize_certificate(c))

    # compute first_theme if available (earliest approved cert)
    first_theme = None
    if certs:
        tm = certs[0].get('training_module')
        first_theme = tm.get('theme') if tm else None

    return {
        'id': trainer.id,
        'full_name': trainer.full_name,
        'mobile_no': trainer.mobile_no,
        'aadhaar_no': trainer.aadhaar_no,
        'empanel_district': trainer.empanel_district,
        'designation': trainer.designation,
        'bank_account_number': trainer.bank_account_number,
        'ifsc': trainer.ifsc,
        'branch_name': trainer.branch_name,
        'bank_name': trainer.bank_name,
        'education': trainer.education,
        'created_at': trainer.created_at.isoformat() if trainer.created_at else None,
        'first_theme': first_theme,
        'certificates': certs,
    }

def approved_trainers_api(request):
    """
    Public API - returns approved (verified) trainers and their approved certificates.
    Query params:
      - page (int, default 1)
      - page_size (int, default 50, max 200)
    """
    # parse pagination params
    page = _int_or(request.GET.get('page'), DEFAULT_PAGE)
    page_size = _int_or(request.GET.get('page_size'), DEFAULT_PAGE_SIZE)
    if page_size < 1:
        page_size = DEFAULT_PAGE_SIZE
    if page_size > MAX_PAGE_SIZE:
        page_size = MAX_PAGE_SIZE
    if page < 1:
        page = 1

    # Base queryset: trainers created/verified via submissions
    qs = MasterTrainer.objects.filter(submissions__profile_verified=True).distinct().order_by('id')

    # Prefetch only approved certificates and their training_module to avoid N+1
    qs = qs.prefetch_related(
        Prefetch(
            'certificates',
            queryset=MasterTrainerCertificate.objects.filter(status='approved').select_related('training_module'),
            to_attr='approved_certificates_prefetched'
        )
    )

    # paginator
    paginator = Paginator(qs, page_size)
    try:
        page_obj = paginator.page(page)
    except EmptyPage:
        # return empty page if requested page beyond range
        page_obj = []

    results = []
    for trainer in page_obj:
        results.append(_serialize_trainer(trainer))

    total_count = paginator.count if hasattr(paginator, 'count') else 0
    total_pages = paginator.num_pages if hasattr(paginator, 'num_pages') else 0

    # next / previous links (absolute URLs). If page_obj is list (EmptyPage), handle gracefully.
    next_url = None
    prev_url = None
    if hasattr(page_obj, 'has_next') and page_obj.has_next():
        next_url = _build_page_url(request, page_obj.next_page_number(), page_size)
    if hasattr(page_obj, 'has_previous') and page_obj.has_previous():
        prev_url = _build_page_url(request, page_obj.previous_page_number(), page_size)

    return JsonResponse({
        'count': total_count,
        'total_pages': total_pages,
        'page': page,
        'page_size': page_size,
        'next': next_url,
        'previous': prev_url,
        'results': results,
    }, json_dumps_params={'indent': 2})
