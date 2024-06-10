from venv import logger
from rest_framework.views import APIView
from rest_framework.response import Response
# Custom imports
from .models import Article
from .serializers import ArticleSerializer
from rest_framework.permissions import IsAuthenticated
from drf_cognito.permissions import IsAdminUser, IsUserUser


class ListCreateArticles(APIView):
    
    permission_classes = [IsAuthenticated, IsUserUser]

    def get(self, request) :
        
        all_artcles = Article.objects.all()
        all_artcles_ser = ArticleSerializer(all_artcles, many=True)

        # import pdb
        # pdb.set_trace()

        return Response({
            "data" : all_artcles_ser.data,
            "user" : {
                "email" : request.user.email,
                "role" : request.user.role
            }
            }
        )