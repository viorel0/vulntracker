from rest_framework import viewsets, generics
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework import status
from .models import ScanInfo
from .serializers import ScanInfoSerializer


class ScanInfoViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ScanInfo.objects.all()
    serializer_class = ScanInfoSerializer
    renderer_classes = [JSONRenderer]


class ScanInfoByShaView(generics.ListAPIView):
    serializer_class = ScanInfoSerializer
    renderer_classes = [JSONRenderer]

    def get_queryset(self):
        sha256 = self.kwargs.get('sha256')
        queryset = ScanInfo.objects.filter(sha256=sha256)
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if not queryset.exists():
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        return super().list(request, *args, **kwargs)
