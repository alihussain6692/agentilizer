import os

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.db.models import Avg, Sum
from django.contrib import messages
from rest_framework import viewsets, status
from rest_framework.response import Response

from .models import AuditJob, AuditResult, CollectiveReport
from .serializers import AuditJobSerializer, AuditResultSerializer, CollectiveReportSerializer
from .services.ede_service import run_ede_audit
from .services.aibom_service import run_aibom_audit
from .services.risk_scorer import compute_combined_score

_SCORE_MAP = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'MINIMAL': 0, 'UNKNOWN': 0}
_SCORE_LABELS = ['MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']


def _highest_risk(scores: list[str]) -> str:
    if not scores:
        return 'UNKNOWN'
    best = max(_SCORE_MAP.get(s.upper(), 0) for s in scores)
    return _SCORE_LABELS[min(best, 4)]


def _create_audit_result(job: AuditJob) -> tuple[AuditResult, dict, dict]:
    """Run both audits and persist the result. Returns (result, ede_dict, aibom_dict)."""
    file_path = job.workflow_file.path
    ede = run_ede_audit(file_path)
    aibom = run_aibom_audit(file_path)
    combined = compute_combined_score(
        ede.get('ede_risk_level', 'UNKNOWN'),
        ede.get('gdpr_flag', False),
        aibom.get('risk_level', 'UNKNOWN'),
        aibom.get('available', False),
    )
    result = AuditResult.objects.create(
        job=job,
        nodes_total=ede.get('nodes_total', 0),
        nodes_assessed=ede.get('nodes_assessed', 0),
        nodes_unassessed=ede.get('nodes_unassessed', 0),
        avg_ede=ede.get('avg_ede', 0.0),
        nodes_with_ede=ede.get('nodes_with_ede', 0),
        unnecessary_pii_total=ede.get('unnecessary_pii_total', 0),
        gdpr_concerns=ede.get('gdpr_concerns', 0),
        gdpr_flag=ede.get('gdpr_flag', False),
        ede_risk_level=ede.get('ede_risk_level', 'UNKNOWN'),
        node_results=ede.get('node_results', []),
        ede_error=ede.get('error', ''),
        aibom_available=aibom.get('available', False),
        aibom_findings=aibom.get('findings', []),
        aibom_total_issues=aibom.get('total_issues', 0),
        aibom_risk_level=aibom.get('risk_level', 'UNKNOWN'),
        aibom_error=aibom.get('error', ''),
        credential_findings=aibom.get('credential_findings', []),
        total_credential_issues=aibom.get('total_credential_issues', 0),
        combined_risk_score=combined,
    )
    return result, ede, aibom


# ── Dashboard ─────────────────────────────────────────────────────────────────

def index(request):
    jobs = AuditJob.objects.select_related('result').all().order_by('-created_at')
    recent_reports = CollectiveReport.objects.all().order_by('-created_at')[:5]

    # Global aggregate stats
    agg = AuditResult.objects.aggregate(
        avg_ede=Avg('avg_ede'),
        total_gdpr=Sum('gdpr_concerns'),
        total_aibom=Sum('aibom_total_issues'),
        total_pii=Sum('unnecessary_pii_total'),
    )
    global_avg_ede = round(agg['avg_ede'] or 0, 2)
    total_gdpr_flags = agg['total_gdpr'] or 0
    total_aibom_issues = agg['total_aibom'] or 0

    # EDE distribution counts for ASCII bar chart
    dist = {
        'HIGH':    AuditResult.objects.filter(ede_risk_level='HIGH').count(),
        'MEDIUM':  AuditResult.objects.filter(ede_risk_level='MEDIUM').count(),
        'LOW':     AuditResult.objects.filter(ede_risk_level='LOW').count(),
        'MINIMAL': AuditResult.objects.filter(ede_risk_level='MINIMAL').count(),
    }
    max_dist = max(dist.values()) if any(dist.values()) else 1
    # Build bar strings (20 chars wide)
    bar_width = 20
    ede_bars = {
        k: '█' * round((v / max_dist) * bar_width) + '░' * (bar_width - round((v / max_dist) * bar_width))
        for k, v in dist.items()
    }

    return render(request, 'audit/index.html', {
        'jobs': jobs,
        'recent_reports': recent_reports,
        'total_jobs': jobs.count(),
        'global_avg_ede': global_avg_ede,
        'total_gdpr_flags': total_gdpr_flags,
        'total_aibom_issues': total_aibom_issues,
        'ede_dist': dist,
        'ede_bars': ede_bars,
    })


# ── Upload / multi-file ───────────────────────────────────────────────────────

def upload(request):
    if request.method == 'POST':
        uploaded_files = request.FILES.getlist('workflow_file')
        if not uploaded_files:
            return render(request, 'audit/upload.html', {'error': 'No file uploaded.'})

        completed_jobs = []
        errors = []

        for uploaded_file in uploaded_files:
            job = AuditJob.objects.create(
                workflow_file=uploaded_file,
                workflow_name=uploaded_file.name,
                status='running',
            )
            try:
                _create_audit_result(job)
                job.status = 'complete'
                job.save()
                completed_jobs.append(job)
            except Exception as e:
                job.status = 'failed'
                job.save()
                errors.append(f"{uploaded_file.name}: {str(e)}")

        if not completed_jobs:
            return render(request, 'audit/upload.html', {'error': ' | '.join(errors)})

        # Single file → individual results page
        if len(completed_jobs) == 1:
            return redirect('results', job_id=completed_jobs[0].id)

        # Multiple files → collective report
        results_qs = [job.result for job in completed_jobs]
        avg_ede = sum(r.avg_ede for r in results_qs) / len(results_qs)
        report = CollectiveReport.objects.create(
            name=f'Batch Audit — {len(completed_jobs)} workflows',
            total_workflows=len(completed_jobs),
            avg_ede_across_all=round(avg_ede, 4),
            total_gdpr_flags=sum(r.gdpr_concerns for r in results_qs),
            total_pii_violations=sum(r.unnecessary_pii_total for r in results_qs),
            highest_risk=_highest_risk([r.combined_risk_score for r in results_qs]),
            total_aibom_issues=sum(r.aibom_total_issues for r in results_qs),
            summary=[{
                'workflow_name':     job.workflow_name,
                'avg_ede':           job.result.avg_ede,
                'ede_risk_level':    job.result.ede_risk_level,
                'gdpr_flag':         job.result.gdpr_flag,
                'combined_risk_score': job.result.combined_risk_score,
                'aibom_total_issues': job.result.aibom_total_issues,
                'job_id':            job.id,
            } for job in completed_jobs],
        )
        report.jobs.set(completed_jobs)
        return redirect('collective_results', report_id=report.id)

    return render(request, 'audit/upload.html')


# ── Individual results ────────────────────────────────────────────────────────

def results(request, job_id):
    job = get_object_or_404(AuditJob, id=job_id)
    result = get_object_or_404(AuditResult, job=job)
    return render(request, 'audit/results.html', {'job': job, 'result': result})


def download_json(request, job_id):
    job = get_object_or_404(AuditJob, id=job_id)
    result = get_object_or_404(AuditResult, job=job)
    data = {
        'workflow': job.workflow_name,
        'audited_at': job.created_at.isoformat(),
        'combined_risk_score': result.combined_risk_score,
        'ede': {
            'avg_ede': result.avg_ede,
            'nodes_total': result.nodes_total,
            'nodes_assessed': result.nodes_assessed,
            'gdpr_flag': result.gdpr_flag,
            'gdpr_concerns': result.gdpr_concerns,
            'unnecessary_pii_total': result.unnecessary_pii_total,
            'risk_level': result.ede_risk_level,
            'node_results': result.node_results,
        },
        'aibom': {
            'available': result.aibom_available,
            'risk_level': result.aibom_risk_level,
            'total_issues': result.aibom_total_issues,
            'findings': result.aibom_findings,
        },
    }
    response = JsonResponse(data, json_dumps_params={'indent': 2})
    response['Content-Disposition'] = f'attachment; filename="agentilizer_{job.workflow_name}.json"'
    return response


# ── Collective / batch report ─────────────────────────────────────────────────

def collective_results(request, report_id):
    report = get_object_or_404(CollectiveReport, id=report_id)
    jobs = report.jobs.select_related('result').all()

    # Risk distribution for stacked bar
    risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'MINIMAL': 0}
    for job in jobs:
        if hasattr(job, 'result'):
            score = job.result.combined_risk_score.upper()
            if score in risk_counts:
                risk_counts[score] += 1

    # Top 3 worst by EDE rate
    sorted_jobs = sorted(
        [j for j in jobs if hasattr(j, 'result')],
        key=lambda j: j.result.avg_ede,
        reverse=True,
    )
    worst_offenders = sorted_jobs[:3]

    return render(request, 'audit/collective_results.html', {
        'report': report,
        'jobs': jobs,
        'risk_counts': risk_counts,
        'worst_offenders': worst_offenders,
    })


def batch_reports(request):
    reports = CollectiveReport.objects.all().order_by('-created_at')
    return render(request, 'audit/batch_reports.html', {'reports': reports})


# ── Delete views ──────────────────────────────────────────────────────────────

def delete_job(request, job_id):
    """Delete a single audit job and its result. Removes uploaded file from disk."""
    if request.method == 'POST':
        job = get_object_or_404(AuditJob, id=job_id)
        job_name = job.workflow_name
        try:
            if job.workflow_file and os.path.exists(job.workflow_file.path):
                os.remove(job.workflow_file.path)
        except Exception:
            pass
        job.delete()
        messages.success(request, f'Audit for "{job_name}" deleted.')
    return redirect('index')


def delete_all_jobs(request):
    """Delete all audit jobs, results, and uploaded files."""
    if request.method == 'POST':
        for job in AuditJob.objects.all():
            try:
                if job.workflow_file and os.path.exists(job.workflow_file.path):
                    os.remove(job.workflow_file.path)
            except Exception:
                pass
        AuditJob.objects.all().delete()
        messages.success(request, 'All audits deleted.')
    return redirect('index')


def delete_batch_report(request, report_id):
    """Delete a collective report and all its associated audit jobs and files."""
    if request.method == 'POST':
        report = get_object_or_404(CollectiveReport, id=report_id)
        job_count = report.jobs.count()
        for job in report.jobs.all():
            try:
                if job.workflow_file and os.path.exists(job.workflow_file.path):
                    os.remove(job.workflow_file.path)
            except Exception:
                pass
        report.jobs.all().delete()
        report.delete()
        messages.success(request, f'Batch report deleted — {job_count} audit(s) removed.')
    return redirect('batch_reports')


# ── DRF API ViewSet ───────────────────────────────────────────────────────────

class AuditViewSet(viewsets.ViewSet):

    def list(self, request):
        jobs = AuditJob.objects.all().order_by('-created_at')
        return Response(AuditJobSerializer(jobs, many=True).data)

    def retrieve(self, request, pk=None):
        job = get_object_or_404(AuditJob, pk=pk)
        return Response(AuditJobSerializer(job).data)

    def create(self, request):
        uploaded_file = request.FILES.get('workflow_file')
        if not uploaded_file:
            return Response({'error': 'No file uploaded.'}, status=status.HTTP_400_BAD_REQUEST)

        job = AuditJob.objects.create(
            workflow_file=uploaded_file,
            workflow_name=uploaded_file.name,
            status='running',
        )
        try:
            _create_audit_result(job)
            job.status = 'complete'
            job.save()
            return Response(AuditJobSerializer(job).data, status=status.HTTP_201_CREATED)
        except Exception as e:
            job.status = 'failed'
            job.save()
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
