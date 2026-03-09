import hashlib
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import ScanJob
from .serializers import ScanJobSerializer
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import uuid
import os
import logging

logger = logging.getLogger(__name__)

# Try to import blake3 for fast hashing
try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False


class FileUploadView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        if 'file' not in request.FILES:
            return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        uploaded_file = request.FILES['file']
        file_name = uploaded_file.name
        file_size = uploaded_file.size
        
        # Validate file size (100MB max)
        if file_size > 104857600:
            return Response(
                {'error': 'File too large. Maximum size is 100MB.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Compute BLAKE3 (primary) and SHA-256 (for VT) in a single pass
        blake3_hash = blake3.blake3() if HAS_BLAKE3 else None
        sha256_hash = hashlib.sha256()
        
        for chunk in uploaded_file.chunks():
            sha256_hash.update(chunk)
            if blake3_hash:
                blake3_hash.update(chunk)
        
        # Use BLAKE3 as primary hash, fallback to SHA-256
        primary_hash = blake3_hash.hexdigest() if blake3_hash else sha256_hash.hexdigest()
        sha256_hex = sha256_hash.hexdigest()

        # Check if already scanned recently (deduplicate by primary hash)
        existing_job = ScanJob.objects.filter(file_hash=primary_hash).order_by('-created_at').first()
        if existing_job and existing_job.status == 'COMPLETED':
            serializer = ScanJobSerializer(existing_job)
            return Response(serializer.data, status=status.HTTP_200_OK)

        # Create new Job
        user = request.user if request.user.is_authenticated else None
        job = ScanJob.objects.create(
            user=user,
            file_name=file_name,
            file_hash=primary_hash,
            sha256_hash=sha256_hex,
            file_size=file_size,
            status='PENDING'
        )

        # Save to temp storage
        uploaded_file.seek(0)
        rel_path = default_storage.save(
            f"temp_scans/{uuid.uuid4()}_{file_name}",
            ContentFile(uploaded_file.read())
        )
        absolute_file_path = default_storage.path(rel_path)

        # Trigger Celery Task
        from .tasks import run_full_scan
        run_full_scan.delay(job.id, absolute_file_path)
        
        logger.info(f"Scan job created: {job.id} for {file_name} (BLAKE3: {primary_hash[:16]}...)")
        
        serializer = ScanJobSerializer(job)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ScanStatusView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, pk, *args, **kwargs):
        try:
            job = ScanJob.objects.get(pk=pk)
            serializer = ScanJobSerializer(job)
            return Response(serializer.data)
        except ScanJob.DoesNotExist:
            return Response({'error': 'Job not found'}, status=status.HTTP_404_NOT_FOUND)
